# Built-in rule catalog

numbat embeds the rules below. They are enabled for detection and do not block
by default. A pre-action hook match describes a requested action, not a
confirmed outcome.

The YAML files in [`rules/`](../rules/) are the authoritative definitions. Run
`numbat rules list` to print the effective rule IDs after operator overrides.
For the rule format and override behavior, see [Writing rules](rules.md).

## Secrets

- `secrets.agent_read_env` - access to a `.env`-style file was observed or
  requested.
- `secrets.read_private_key` - read an SSH private key, AWS credentials, a kube
  config, package-manager credentials, or a Docker registry config.
- `secrets.cloud_credential_read` - access to gcloud application-default
  credentials or GitHub CLI host tokens.
- `secrets.browser_session_store_read` - read a browser cookie, login, or key
  database from a browser profile.
- `secrets.cloud_secret_manager_read` - request a secret value from AWS, GCP,
  Azure, Kubernetes, or HashiCorp Vault.
- `secrets.workload_identity_token_read` - read a projected Kubernetes, EKS, or
  Azure workload identity token.
- `secrets.developer_credential_read` - read a Git, netrc, PostgreSQL, Hugging
  Face, Poetry, or Kaggle credential store.
- `secrets.process_environment_read` - read a Linux process environment block
  from `/proc`.

## Exfiltration

- `exfil.env_capture_to_network` - one command supplies captured environment
  output or a known credential file to a data-bearing `curl` or `wget` request.
- `exfil.curl_post_file` - a credential, browser-session, workload-token, or
  process-environment file is referenced in a curl data or form request.
- `exfil.dns_tunnel_exec` - a DNS resolver is run with a query name built from
  command substitution or backticks.
- `exfil.secret_read_and_egress_oneliner` - one command requests a
  secret-manager value and proposes a data-bearing `curl` or `wget` transfer to
  a non-loopback HTTP(S) endpoint.

## Integrity

- `integrity.git_hooks_bypass` - a Git commit or push bypasses hooks, or
  `core.hooksPath` is disabled.
- `integrity.history_tamper` - a command disables, clears, or deletes shell
  history.

## Execution

- `exec.download_pipe_shell` - a `curl` or `wget` download is piped directly
  into an interpreter.
- `exec.reverse_shell` - an interactive shell is connected over a network
  transport using a recognized shell, netcat, ncat, or socat form.
- `exec.reverse_tunnel` - an SSH remote forward or an explicit Chisel or Ligolo
  reverse tunnel is requested; local and dynamic local SSH forwards are
  excluded.
- `exec.encoded_payload_shell` - base64-decoded content is piped directly into
  a shell.
- `exec.destructive_recursive_delete` - `rm -rf` targets filesystem root or the
  user's home directory.
- `exec.agent_runtime_bypass_flags` - a supported endpoint agent is launched
  with a known approval, permission, or sandbox bypass flag.

## Reconnaissance

- `recon.cloud_metadata` - a fetch targets a cloud instance-metadata service.
- `recon.privilege_escalation` - a command lists sudo grants or recursively
  searches system roots for setid files and file capabilities.
- `recon.network_sweep` - a named scanner is given an explicit scan or
  target-list option and a network range.

## Privilege

- `privilege.sudoers_tamper` - an action targets `/etc/sudoers` or
  `/etc/sudoers.d/*` for modification.
- `privilege.container_host_escape` - Docker or Podman is launched with
  host-escape primitives such as privileged mode, host namespaces, root bind
  mounts, added capabilities, or the Docker socket.
- `privilege.access_control_mutation` - a command requests a setuid bit,
  dangerous Linux capability, or protected-path access-control change.
- `privilege.elevated_shell` - an interactive root shell is requested through
  `sudo`, `doas`, `su`, or `pkexec`.
- `privilege.container_runtime_socket_access` - a client or runtime CLI
  addresses a Docker, containerd, CRI-O, or Podman control socket.
- `privilege.host_namespace_entry` - a command requests PID 1 namespace or
  `/proc/1/root` access across a container boundary.
- `privilege.kernel_module_change` - a command requests insertion or removal of a
  kernel module with `insmod`, `rmmod`, or `modprobe`; query and dry-run forms are
  excluded.

## Lateral movement

- `lateral.workload_exec` - execution or debugging in another workload is
  requested through a cluster, low-level runtime, or explicitly remote
  container daemon.

## Impact

- `impact.cryptomining_launch` - execution of a known cryptocurrency miner
  binary, container entrypoint, or exact image basename is requested or
  observed.
- `impact.disk_wipe` - a destructive disk, partition, filesystem, block-device,
  or Windows-volume operation is requested; no-op modes and loop or RAM devices
  are excluded.
- `impact.fork_bomb` - a canonical unbounded recursive-fork payload is
  requested.
- `impact.mass_process_termination` - a command requests force-killing every
  accessible process.

## Source control

- `source.git_remote_tamper` - a Git remote or URL rewrite is added or changed.
  Force pushes require repository policy context and are not classified by
  this rule.
- `source.git_config_exec` - a Git setting can invoke an external program
  during normal Git operations. The exact bare `!gh auth git-credential`
  helper form is excluded; path-qualified and extended shell helpers remain
  detectable.

## Tampering

- `tamper.agent_config_write` - a command or structured action mutates an agent
  configuration surface used to load numbat hooks or plugins.
- `tamper.detector_state_write` - a command or structured action targets the
  default per-user `$HOME/.numbat` state directory.
- `tamper.guardrails_off` - the session uses a reduced-approval permission
  mode.

## Persistence

- `persistence.shell_profile_write` - a command or structured action modifies a
  shell startup file.
- `persistence.scheduler_install` - a command requests a scheduled or
  background job, or targets a standard scheduler or autostart path.
- `persistence.git_hook_write` - a command or structured action modifies a
  `.git/hooks/` path, excluding `.sample` stubs.
- `persistence.ssh_authorized_keys` - a structured action writes a user
  `authorized_keys` file or Windows administrators key file.
- `persistence.ssh_authorized_keys_command` - a shell or PowerShell command
  modifies `authorized_keys`.
- `persistence.privileged_account_change` - a command requests UID 0 or
  membership in a privileged local, domain, container-control, or remote-login
  group.

## Sequences

Sequence rules match ordered steps within one correlation window.

- `chain.secret_read_then_egress` - secret-bearing file access followed by a
  proposed data-bearing outbound action.
- `chain.secret_manager_read_then_egress` - a secret-manager value request
  followed by a proposed data- or credential-bearing outbound action.
- `chain.guardrails_off_then_egress` - reduced-approval mode followed by a
  proposed data-bearing outbound action.
- `chain.permission_denied_then_runtime_bypass` - a typed permission denial
  followed by a child-agent launch with explicit bypass flags.
- `chain.workload_identity_then_lateral_execution` - workload-token access
  followed by requested execution in another workload or remote runtime.
- `chain.privilege_discovery_then_elevation` - privilege-path enumeration
  followed by an elevation-capable shell, PID-1 namespace, or runtime-socket
  action.

The three egress sequences share the same outbound-action predicate. It covers
data-bearing `curl` or `wget` requests to non-loopback HTTP(S) endpoints;
explicit-payload inline Python, Node, or PowerShell HTTP writes; remote `scp` or
`rsync`; and send, upload, share, publish, mail, or message-posting MCP tools.
Read, list, search, and delete-style MCP verbs are excluded.
