# Tetragon unlink issue

## Prerequisite
### Install Tetragon
```
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon ${EXTRA_HELM_FLAGS[@]} cilium/tetragon -n kube-system
kubectl rollout status -n kube-system ds/tetragon -w
```

### Install sample application

```
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/v1.15.3/examples/minikube/http-sw-app.yaml
```

### Apply Tetragon File Monitoring Enforce policy

Tetragon as part of its enforcement examples provides a way to apply [File Monitoring Enforce policy](https://tetragon.io/docs/getting-started/enforcement/#enforce-file-access-restrictions). The specific policy can be found [here](https://github.com/cilium/tetragon/blob/main/examples/quickstart/file_monitoring_enforce.yaml).

The aim of this policy is to kill any process accessing `/etc/` folder.

Thus any attempts to access/update sensitive assets (for example `/etc/shadow`) will be killed.

The example actions that are handled by the enforcement policy are:
* `security_file_permission`
* `security_mmap_file`
* `security_path_truncate`
* ... few others

**Note that `security_unlink_path` is not part of this action** i.e., the attacker can unlink/delete the sensitive file. We updated the enforcement policy to add `security_unlink_path`. The updated yaml can be found [here](https://github.com/nyrahul/RuntimeSecurity/blob/main/tetragon-file-monitoring-enforce/file_monitoring_enforce_unlink.yaml#L7-L37).

After applying this updated policy we tried to rm a sensitive file (`rm /etc/shadow`). The specific steps that were taken are:

* Check for the presence of sensitive file `/etc/shadow`.
```
❯ kubectl exec -ti xwing -- sh -c "ls -l /etc/shadow"
-rw-r----- 1 root shadow 500 Dec 19  2023 /etc/shadow
```

* Delete the sensitive file `/etc/shadow`.
```
❯ kubectl exec -ti xwing -- sh -c "rm /etc/shadow"
Killed
command terminated with exit code 137
```
Note that the process attempting to delete the sensitive asset was killed i.e., we assumed that Tetragon was able to thwart the deletion attempt. However, when we checked for the sensitive asset, we couldn't find it:
```
❯ kubectl exec -ti xwing -- sh -c "ls -l /etc/shadow"
ls: cannot access '/etc/shadow': No such file or directory
command terminated with exit code 2
```

```
...
🚀 process default/xwing /usr/bin/sh -c "ls -l /etc/shadow"
🚀 process default/xwing /usr/bin/ls -l /etc/shadow
💥 exit    default/xwing /usr/bin/ls -l /etc/shadow 0
💥 exit    default/xwing /usr/bin/sh -c "ls -l /etc/shadow" 0
🚀 process default/xwing /usr/bin/rm /etc/shadow
❓ syscall default/xwing /usr/bin/rm security_path_unlink
💥 exit    default/xwing /usr/bin/rm /etc/shadow SIGKILL
🚀 process default/xwing /usr/bin/sh -c "ls -l /etc/shadow"
🚀 process default/xwing /usr/bin/ls -l /etc/shadow
💥 exit    default/xwing /usr/bin/ls -l /etc/shadow 2
💥 exit    default/xwing /usr/bin/sh -c "ls -l /etc/shadow" 2
🚀 process default/xwing /usr/bin/sh -c "rm /etc/shadow"
💥 exit    default/xwing /usr/bin/sh -c "rm /etc/shadow" 137
```

Thus, the impact of post-attack mitigation was that the kill signal was handled after the deletion was attempted and thus the sensitive asset could not be saved.

## Summary
Tetragon enforcement uses a post-attack mitigation techniques such as `bpf_send_signal()`. In this case, it was shown that the sensitive asset unlink could not be prevented even though the policy rules were executed (i.e., the target process was killed). The mitigation kicked in too late, after the asset was deleted.

