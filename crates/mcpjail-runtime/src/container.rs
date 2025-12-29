//! Container management for MCP servers

use bollard::container::{
    Config, CreateContainerOptions, RemoveContainerOptions, StartContainerOptions,
    AttachContainerOptions, AttachContainerResults,
};
use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
use bollard::models::{HostConfig, Mount, MountTypeEnum, DeviceMapping};
use bollard::Docker;
use futures::StreamExt;
use mcpjail_policy::Policy;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

use crate::error::RuntimeError;
use crate::security::{SeccompProfile, dropped_capabilities, security_opts};

/// Container runtime for MCP servers
pub struct ContainerRuntime {
    docker: Docker,
    seccomp_profile_path: Option<String>,
}

impl ContainerRuntime {
    /// Create a new container runtime
    pub async fn new() -> Result<Self, RuntimeError> {
        let docker = Docker::connect_with_local_defaults()?;

        // Verify Docker is accessible
        docker.ping().await?;

        Ok(Self {
            docker,
            seccomp_profile_path: None,
        })
    }

    /// Set custom seccomp profile path
    pub fn with_seccomp_profile(mut self, path: String) -> Self {
        self.seccomp_profile_path = Some(path);
        self
    }

    /// Create and start a container for an MCP server
    pub async fn create_container(
        &self,
        name: &str,
        image: &str,
        command: Vec<String>,
        policy: &Policy,
        env_vars: HashMap<String, String>,
        working_dir: Option<String>,
    ) -> Result<String, RuntimeError> {
        let container_name = format!("mcpjail-{}", name);

        // Build mounts from policy
        let mounts = self.build_mounts(policy)?;

        // Build environment variables (sanitized)
        let env: Vec<String> = env_vars
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();

        // Build host config with security settings
        let host_config = HostConfig {
            network_mode: Some(policy.docker_network_mode().to_string()),
            memory: Some(policy.memory_bytes() as i64),
            memory_swap: Some(policy.memory_bytes() as i64), // No swap
            cpu_period: Some(100000),
            cpu_quota: Some((policy.resources.cpu * 100000.0) as i64),
            pids_limit: Some(policy.resources.pids as i64),
            readonly_rootfs: Some(true),
            cap_drop: Some(dropped_capabilities()),
            security_opt: Some(security_opts(self.seccomp_profile_path.as_deref())),
            mounts: Some(mounts),
            auto_remove: Some(true),
            ..Default::default()
        };

        let config = Config {
            image: Some(image.to_string()),
            cmd: Some(command),
            env: Some(env),
            working_dir: working_dir,
            host_config: Some(host_config),
            attach_stdin: Some(true),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            open_stdin: Some(true),
            stdin_once: Some(false),
            tty: Some(false),
            ..Default::default()
        };

        // Remove existing container if any
        let _ = self.docker.remove_container(
            &container_name,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        ).await;

        // Create container
        let options = CreateContainerOptions {
            name: &container_name,
            platform: None,
        };

        let response = self.docker.create_container(Some(options), config).await?;
        info!("Created container: {}", response.id);

        Ok(response.id)
    }

    /// Build mount configurations from policy
    fn build_mounts(&self, policy: &Policy) -> Result<Vec<Mount>, RuntimeError> {
        let mut mounts = Vec::new();

        for mount_config in &policy.filesystem.mounts {
            let read_only = mount_config.mode == "ro";

            // Check if this is a tmpfs mount (has size limit)
            if let Some(_size) = &mount_config.size {
                mounts.push(Mount {
                    target: Some(mount_config.path.clone()),
                    typ: Some(MountTypeEnum::TMPFS),
                    read_only: Some(read_only),
                    ..Default::default()
                });
            } else {
                mounts.push(Mount {
                    target: Some(mount_config.path.clone()),
                    source: Some(mount_config.path.clone()),
                    typ: Some(MountTypeEnum::BIND),
                    read_only: Some(read_only),
                    ..Default::default()
                });
            }
        }

        // Always add a writable /tmp if not already present
        if !mounts.iter().any(|m| m.target.as_deref() == Some("/tmp")) {
            mounts.push(Mount {
                target: Some("/tmp".to_string()),
                typ: Some(MountTypeEnum::TMPFS),
                read_only: Some(false),
                ..Default::default()
            });
        }

        Ok(mounts)
    }

    /// Start a container and attach to its stdio
    pub async fn start_and_attach(
        &self,
        container_id: &str,
    ) -> Result<AttachContainerResults, RuntimeError> {
        // Start the container
        self.docker
            .start_container(container_id, None::<StartContainerOptions<String>>)
            .await?;

        info!("Started container: {}", container_id);

        // Attach to the container
        let attach_options = AttachContainerOptions::<String> {
            stdin: Some(true),
            stdout: Some(true),
            stderr: Some(true),
            stream: Some(true),
            logs: Some(false),
            detach_keys: None,
        };

        let results = self.docker.attach_container(container_id, Some(attach_options)).await?;

        Ok(results)
    }

    /// Stop and remove a container
    pub async fn stop_container(&self, container_id: &str) -> Result<(), RuntimeError> {
        // Stop the container (with timeout)
        let _ = self.docker
            .stop_container(container_id, None)
            .await;

        // Remove the container
        let _ = self.docker.remove_container(
            container_id,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        ).await;

        info!("Stopped container: {}", container_id);
        Ok(())
    }

    /// Check if an image exists locally
    pub async fn image_exists(&self, image: &str) -> bool {
        self.docker.inspect_image(image).await.is_ok()
    }

    /// Pull an image if it doesn't exist
    pub async fn ensure_image(&self, image: &str) -> Result<(), RuntimeError> {
        if !self.image_exists(image).await {
            info!("Pulling image: {}", image);
            use bollard::image::CreateImageOptions;
            use futures::TryStreamExt;

            let options = CreateImageOptions {
                from_image: image,
                ..Default::default()
            };

            let mut stream = self.docker.create_image(Some(options), None, None);
            while let Some(result) = stream.next().await {
                match result {
                    Ok(info) => {
                        if let Some(status) = info.status {
                            debug!("Pull status: {}", status);
                        }
                    }
                    Err(e) => {
                        warn!("Pull warning: {}", e);
                    }
                }
            }
        }
        Ok(())
    }
}

/// Select appropriate base image for the command
pub fn select_base_image(command: &[String]) -> &'static str {
    if command.is_empty() {
        return "node:20-slim";
    }

    let cmd = command[0].to_lowercase();

    if cmd.contains("python") || cmd.contains("pip") {
        "python:3.11-slim"
    } else if cmd.contains("node") || cmd.contains("npm") || cmd.contains("npx") {
        "node:20-slim"
    } else if cmd.contains("deno") {
        "denoland/deno:latest"
    } else if cmd.contains("bun") {
        "oven/bun:latest"
    } else {
        // Default to node for npm-based MCP servers
        "node:20-slim"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_base_image() {
        assert_eq!(select_base_image(&["python".to_string()]), "python:3.11-slim");
        assert_eq!(select_base_image(&["npx".to_string()]), "node:20-slim");
        assert_eq!(select_base_image(&["node".to_string()]), "node:20-slim");
    }
}
