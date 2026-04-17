# Kubernetes

Deep View analyses against offline evidence fan out well across a
Kubernetes cluster: each `Job` picks up a single image from a shared
volume, writes its report, and exits. This page ships a reference
`Job` manifest, a `ConfigMap` for `~/.deepview/config.toml`, and the
`SecurityContext` tradeoffs that come with live acquisition.

!!! warning "Evidence mounts leave the node"
    A `PersistentVolume` backed by block storage is readable by any
    pod that can mount it. Scope your PV access policies the same way
    you would scope physical evidence drive access — isolated
    namespace, RBAC-gated, audited. See
    [operator OPSEC](../security/opsec.md) for chain-of-custody
    implications of sharing evidence across a cluster.

## Prerequisites

- A registry reachable from the cluster that hosts the
  [Deep View Docker image](docker.md).
- A `PersistentVolume` with the acquired evidence images and a
  separate writable `PersistentVolume` for reports and session
  databases.
- A namespace dedicated to forensic casework (`forensics-prod`
  in the examples below) with RBAC locked down to the on-call
  responders.

## Evidence and report volumes

Mount evidence as `ReadOnlyMany` and reports as `ReadWriteMany`. Both
PVCs should request retention annotations so the cluster autoscaler
does not reap them between jobs.

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: evidence
  namespace: forensics-prod
  annotations:
    forensics.deepview/retain: "chain-of-custody"
spec:
  accessModes: [ "ReadOnlyMany" ]
  storageClassName: evidence-rox
  resources:
    requests:
      storage: 512Gi
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: reports
  namespace: forensics-prod
spec:
  accessModes: [ "ReadWriteMany" ]
  storageClassName: reports-rwx
  resources:
    requests:
      storage: 256Gi
```

## ConfigMap for the toolkit config

Deep View reads `~/.deepview/config.toml` by default (or whatever
`DEEPVIEW_CONFIG` points at). A `ConfigMap` keeps the file version-
controlled and mountable into every Job pod without rebuilding the
image.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: deepview-config
  namespace: forensics-prod
data:
  config.toml: |
    # Lab-wide policy — per-job overrides via env vars.
    [acquisition]
    evidence_dir = "/evidence"

    [reporting]
    output_dir   = "/reports"
    formats      = ["json", "html", "stix"]

    [memory]
    # Prefer memprocfs over Volatility for Windows images; falls back
    # automatically when the dump doesn't match.
    engine_priority = ["memprocfs", "volatility"]

    [tracing]
    # We never run the live tracer in a batch job — force the provider
    # to refuse if something tries.
    live_providers_enabled = false

    [reporting.redact]
    # The cluster is multi-tenant; redact environment variables in
    # process dumps before reports leave the namespace.
    process_env = true
```

Mount it at `/etc/deepview/config.toml` and point `DEEPVIEW_CONFIG`
at it.

## Job manifest

The `Job` below scans a single LiME image and writes a report. Fan
out by templating this manifest per evidence file (Argo Workflows,
Helm, Kustomize, whatever your cluster uses for generators).

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: memscan-2026-04-14-hostA
  namespace: forensics-prod
  labels:
    app.kubernetes.io/name: deepview
    forensics.deepview/case: "CASE-2026-00421"
spec:
  backoffLimit: 1              # Evidence runs must be deterministic.
  ttlSecondsAfterFinished: 259200   # 3 days for log ingestion.
  template:
    metadata:
      labels:
        app.kubernetes.io/name: deepview
        forensics.deepview/case: "CASE-2026-00421"
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: deepview
          image: registry.internal.lab/deepview:0.2.0
          imagePullPolicy: IfNotPresent
          args:
            - memory
            - scan
            - --image
            - /evidence/CASE-2026-00421/hostA.lime
            - --output
            - /reports/CASE-2026-00421/hostA.json
          env:
            - name: DEEPVIEW_CONFIG
              value: /etc/deepview/config.toml
            - name: DEEPVIEW_REPORTING__RUN_ID
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
          resources:
            requests:
              cpu: "2"
              memory: "8Gi"
            limits:
              cpu: "4"
              memory: "16Gi"
          volumeMounts:
            - name: evidence
              mountPath: /evidence
              readOnly: true
            - name: reports
              mountPath: /reports
            - name: config
              mountPath: /etc/deepview
              readOnly: true
            - name: cache
              mountPath: /var/cache/deepview
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ "ALL" ]
      volumes:
        - name: evidence
          persistentVolumeClaim:
            claimName: evidence
            readOnly: true
        - name: reports
          persistentVolumeClaim:
            claimName: reports
        - name: config
          configMap:
            name: deepview-config
            items:
              - key: config.toml
                path: config.toml
        - name: cache
          emptyDir:
            sizeLimit: 2Gi
```

## Resource sizing

Two Deep View subsystems drive memory ceilings harder than the rest:

- **Container unlock** (`unlock-luks`, `unlock-veracrypt`) — the
  Argon2id paths hold a working set proportional to the KDF memory
  cost. A 64 MiB × 4-lane Argon2id run needs ~256 MiB resident per
  candidate, and the ProcessPool defaults to `nproc` workers. Budget
  `nproc × kdf_memory × 1.5` as the memory limit.
- **ECC decode** of a large flash image — the BCH decoder via
  `galois` allocates GF(2^13) lookup tables that stay resident for
  the life of the process. Budget ~1 GiB headroom on top of the
  image size.

Typical resource requests:

| Workload | CPU request / limit | Memory request / limit |
| --- | --- | --- |
| Offline `memory scan` (8 GiB image) | 2 / 4 | 8 Gi / 16 Gi |
| Offline `memory analyze --full` | 4 / 8 | 16 Gi / 32 Gi |
| Container unlock (batch of 10 k) | 8 / 16 | 16 Gi / 32 Gi |
| ECC decode (64 GiB flash) | 4 / 8 | 12 Gi / 24 Gi |
| Disassembly + Ghidra headless | 4 / 8 | 12 Gi / 24 Gi |

!!! tip "`GOMEMLIMIT`-style signal"
    Deep View respects `DEEPVIEW_MEMORY__SOFT_LIMIT_BYTES`. Set it to
    80 % of the cgroup limit so the memory engine bails out before
    the OOM killer does, producing a graceful `PluginResult` instead
    of an opaque pod termination.

## SecurityContext tradeoffs

The manifest above runs as non-root with every capability dropped.
That is the right default for **offline** analysis. Two subsystems
need more:

- **Live acquisition (LiME, WinPMem, DMA)** — needs `--privileged`
  equivalents. Run these jobs on a dedicated acquisition node with a
  node selector and taint, never on shared worker pools:

  ```yaml
  spec:
    template:
      spec:
        nodeSelector:
          forensics.deepview/node-class: acquisition
        tolerations:
          - key: forensics.deepview/dedicated
            operator: Equal
            value: acquisition
            effect: NoSchedule
        containers:
          - name: deepview
            securityContext:
              privileged: true
              runAsUser: 0
              capabilities:
                drop: [ "ALL" ]
                add: [ "SYS_ADMIN", "SYS_RAWIO" ]
  ```

- **Live tracing (eBPF)** — uses the capability-narrowed form
  described in the [Docker guide](docker.md#minimum-privilege-trace-recipe):
  `SYS_ADMIN` + `BPF` + `PERFMON`, `hostPID: true`, and a bind mount
  of `/sys/fs/bpf`. Prefer batch replays of pre-recorded
  `SessionStore` files in a shared cluster and keep the live path on
  a dedicated host.

!!! danger "Never run a privileged Deep View on a multi-tenant node"
    A privileged pod can read any kernel memory, mount any volume,
    and load kernel modules. If the cluster is shared with non-
    forensics workloads, a privileged acquisition pod puts **every
    other tenant's data** inside the chain of custody.

## NetworkPolicy

Forensic jobs should not reach the internet. Bind with a deny-all
egress `NetworkPolicy` on the namespace; whitelist only the internal
report sink:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deepview-egress-restricted
  namespace: forensics-prod
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: deepview
  policyTypes: [ "Egress" ]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: forensics-reports
      ports:
        - protocol: TCP
          port: 443
```

## Observability

Each Job emits structured JSON logs via structlog by default. Scrape
them with your existing logging stack; the `forensics.deepview/case`
label makes per-case aggregation trivial. If you also run Deep View's
[Elastic integration](../integrations/index.md), wire the
`EventClassifiedEvent` stream to the same Elasticsearch index and
correlate job metadata with plugin findings.

## Next

- Keep `doctor` in the CI pipeline with the
  [GitHub Actions recipe](ci-cd.md).
- For single-node lab setups where Kubernetes is overkill, see the
  [isolated lab](isolated-lab.md) guide.
