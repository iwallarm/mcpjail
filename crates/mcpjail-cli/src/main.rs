//! MCP Jail - Secure MCP Server Sandbox
//!
//! Run any MCP server with zero trust, zero risk.
//! https://mcpjail.com

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use futures::StreamExt;
use mcpjail_policy::{get_builtin_policy, list_builtin_policies, Policy};
use mcpjail_proxy::{JsonRpcRequest, JsonRpcResponse, ResponseFilter, Validator};
use mcpjail_runtime::{
    ContainerRuntime, select_base_image,
    is_macos, is_sandbox_available, generate_sandbox_profile,
    write_sandbox_profile, create_sandboxed_command, cleanup_profile,
};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "mcpjail")]
#[command(author = "MCP Jail Team <hello@mcpjail.com>")]
#[command(version = "0.1.0")]
#[command(about = "Secure sandbox for MCP servers - https://mcpjail.com", long_about = None)]
struct Cli {
    /// Policy to apply (strict, readonly, development, network-isolated)
    #[arg(long, short, default_value = "strict")]
    policy: String,

    /// Custom policy file path
    #[arg(long)]
    policy_file: Option<PathBuf>,

    /// Allow specific host for network access
    #[arg(long, action = clap::ArgAction::Append)]
    allow_host: Vec<String>,

    /// Mount a path (format: host_path:container_path:mode)
    #[arg(long, short, action = clap::ArgAction::Append)]
    mount: Vec<String>,

    /// Enable verbose logging
    #[arg(long, short)]
    verbose: bool,

    /// Dry run - show what would be done without running
    #[arg(long)]
    dry_run: bool,

    /// Allow exec/shell tools (less secure)
    #[arg(long)]
    allow_exec: bool,

    /// Force local mode (no Docker, proxy validation only)
    #[arg(long)]
    no_docker: bool,

    #[command(subcommand)]
    command: Option<Commands>,

    /// Command to run (when no subcommand)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run an MCP server in a sandbox
    Run {
        /// Command to run
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// List available policies
    Policies,

    /// Show policy details
    Policy {
        /// Policy name
        name: String,
    },

    /// Generate a policy from a dry run
    Learn {
        /// Command to run
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = if cli.verbose { Level::DEBUG } else { Level::WARN };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    match cli.command {
        Some(Commands::Policies) => {
            list_policies();
            Ok(())
        }
        Some(Commands::Policy { name }) => {
            show_policy(&name)?;
            Ok(())
        }
        Some(Commands::Learn { ref command }) => {
            learn_mode(command).await
        }
        Some(Commands::Run { ref command }) => {
            run_sandboxed(&cli, command.clone()).await
        }
        None => {
            if cli.args.is_empty() {
                eprintln!("MCP Jail - Secure MCP Server Sandbox");
                eprintln!("https://mcpjail.com");
                eprintln!();
                eprintln!("Usage: mcpjail [OPTIONS] <COMMAND>");
                eprintln!("       mcpjail --help for more information");
                std::process::exit(1);
            }
            run_sandboxed(&cli, cli.args.clone()).await
        }
    }
}

fn list_policies() {
    println!("Available policies:");
    for name in list_builtin_policies() {
        let policy = get_builtin_policy(name).unwrap();
        println!("  {} - network: {:?}, tools: {:?}",
            name,
            policy.network.mode,
            policy.tools.mode
        );
    }
    println!();
    println!("Learn more at https://mcpjail.com/docs/policies");
}

fn show_policy(name: &str) -> Result<()> {
    let policy = get_builtin_policy(name)
        .context(format!("Unknown policy: {}", name))?;

    let yaml = policy.to_yaml()?;
    println!("{}", yaml);
    Ok(())
}

async fn learn_mode(command: &[String]) -> Result<()> {
    eprintln!("Learn mode not yet implemented");
    eprintln!("Would run: {:?}", command);
    eprintln!("And generate a policy based on observed behavior");
    eprintln!();
    eprintln!("Coming soon! Follow https://mcpjail.com for updates.");
    Ok(())
}

async fn run_sandboxed(cli: &Cli, command: Vec<String>) -> Result<()> {
    if command.is_empty() {
        anyhow::bail!("No command specified");
    }

    // Load policy
    let mut policy = if let Some(path) = &cli.policy_file {
        Policy::from_file(path)?
    } else {
        get_builtin_policy(&cli.policy)
            .context(format!("Unknown policy: {}", cli.policy))?
    };

    // Apply CLI overrides
    for host in &cli.allow_host {
        policy.network.allowed_hosts.push(host.clone());
        policy.network.mode = mcpjail_policy::NetworkMode::Allowlist;
    }

    for mount_spec in &cli.mount {
        if let Some(mount) = parse_mount_spec(mount_spec) {
            policy.filesystem.mounts.push(mount);
        }
    }

    if cli.allow_exec {
        // Remove exec from blocked list
        policy.tools.blocked.retain(|t| !t.contains("exec") && !t.contains("shell"));
    }

    debug!("Starting MCP Jail with policy: {}", policy.name);
    debug!("Command: {:?}", command);

    if cli.dry_run {
        eprintln!("Dry run - would execute:");
        eprintln!("  Image: {}", select_base_image(&command));
        eprintln!("  Command: {:?}", command);
        eprintln!("  Policy: {}", policy.name);
        eprintln!("  Network: {:?}", policy.network.mode);
        eprintln!("  Mounts: {} configured", policy.filesystem.mounts.len());
        return Ok(());
    }

    // Try Docker first (unless --no-docker)
    if !cli.no_docker {
        match ContainerRuntime::new().await {
            Ok(runtime) => {
                info!("Docker available - running in isolated container");
                return run_in_container(runtime, command, policy).await;
            }
            Err(e) => {
                debug!("Docker not available: {}", e);

                // On macOS, try sandbox-exec as fallback
                if is_macos() && is_sandbox_available().await {
                    info!("macOS detected - using sandbox-exec for isolation");
                    eprintln!("NOTE: Using macOS sandbox (no Docker). Install Docker for full isolation.");
                    return run_in_macos_sandbox(command, policy).await;
                }

                // No isolation available
                warn!("No container isolation available");
                eprintln!("WARNING: No container isolation available.");
                if is_macos() {
                    eprintln!("         sandbox-exec not found. Running with proxy validation only.");
                } else {
                    eprintln!("         Install Docker for full security. See https://mcpjail.com/docs/docker");
                }
                eprintln!();
            }
        }
    }

    // Fallback: proxy-only mode (no container isolation)
    run_proxy_only(command, policy).await
}

fn parse_mount_spec(spec: &str) -> Option<mcpjail_policy::MountConfig> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.len() {
        2 => Some(mcpjail_policy::MountConfig {
            path: parts[0].to_string(),
            mode: "ro".to_string(),
            size: None,
        }),
        3 => Some(mcpjail_policy::MountConfig {
            path: parts[0].to_string(),
            mode: parts[2].to_string(),
            size: None,
        }),
        _ => {
            warn!("Invalid mount spec: {}", spec);
            None
        }
    }
}

/// Run MCP server inside a hardened Docker container with full isolation
async fn run_in_container(
    runtime: ContainerRuntime,
    command: Vec<String>,
    policy: Policy,
) -> Result<()> {
    use bollard::container::LogOutput;

    let image = select_base_image(&command);
    let container_name = format!("mcp-{}", std::process::id());

    // Ensure image is available
    runtime.ensure_image(image).await
        .context("Failed to pull container image")?;

    // Create environment - only pass through safe env vars
    let env_vars: HashMap<String, String> = std::env::vars()
        .filter(|(k, _)| {
            // Only pass through safe environment variables
            k == "PATH" ||
            k == "HOME" ||
            k == "TERM" ||
            k == "LANG" ||
            k == "LC_ALL" ||
            k.starts_with("MCP_") // Allow MCP-specific vars
        })
        .collect();

    // Create container
    let container_id = runtime.create_container(
        &container_name,
        image,
        command.clone(),
        &policy,
        env_vars,
        Some("/workspace".to_string()),
    ).await.context("Failed to create container")?;

    info!("Created container: {}", container_id);

    // Start and attach to container
    let attach_result = runtime.start_and_attach(&container_id).await
        .context("Failed to start container")?;

    let validator = Validator::new(policy.clone());
    let filter = ResponseFilter::new();

    // Get input and output streams from attach result
    let mut container_input = attach_result.input;
    let mut container_output = attach_result.output;

    // Proxy stdin -> container with validation
    let stdin_validator = validator.clone();
    let stdin_handle = tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let mut reader = TokioBufReader::new(stdin);
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // EOF
                Ok(_) => {
                    // Parse and validate request
                    match serde_json::from_str::<JsonRpcRequest>(&line) {
                        Ok(request) => {
                            debug!("Request: {} (id: {:?})", request.method, request.id);

                            // Validate against policy
                            if let Err(e) = stdin_validator.validate_request(&request) {
                                error!("Request blocked: {}", e);

                                // Send error response to stdout
                                let error_response = JsonRpcResponse::error(
                                    request.id,
                                    -32001,
                                    format!("MCP Jail policy violation: {}", e),
                                );
                                let error_json = serde_json::to_string(&error_response).unwrap();
                                println!("{}", error_json);
                                continue;
                            }
                        }
                        Err(e) => {
                            debug!("Non-JSON-RPC message: {}", e);
                        }
                    }

                    // Forward to container
                    if let Err(e) = container_input.write_all(line.as_bytes()).await {
                        error!("Failed to write to container: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to read stdin: {}", e);
                    break;
                }
            }
        }
    });

    // Proxy container output -> stdout with filtering
    let stdout_handle = tokio::spawn(async move {
        while let Some(result) = container_output.next().await {
            match result {
                Ok(output) => {
                    let data = match output {
                        LogOutput::StdOut { message } => message,
                        LogOutput::StdErr { message } => {
                            // Forward stderr to stderr
                            let _ = tokio::io::stderr().write_all(&message).await;
                            continue;
                        }
                        _ => continue,
                    };

                    // Try to parse as JSON for filtering
                    if let Ok(text) = std::str::from_utf8(&data) {
                        for line in text.lines() {
                            match serde_json::from_str::<serde_json::Value>(line) {
                                Ok(mut response) => {
                                    filter.filter(&mut response);
                                    let filtered_json = serde_json::to_string(&response).unwrap();
                                    println!("{}", filtered_json);
                                }
                                Err(_) => {
                                    // Pass through non-JSON
                                    println!("{}", line);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Container output error: {}", e);
                    break;
                }
            }
        }
    });

    // Wait for either handle to complete
    tokio::select! {
        _ = stdin_handle => {
            debug!("Stdin handler completed");
        }
        _ = stdout_handle => {
            debug!("Stdout handler completed");
        }
    }

    // Clean up container
    let _ = runtime.stop_container(&container_id).await;
    info!("Container stopped");

    Ok(())
}

/// Run MCP server in macOS sandbox using sandbox-exec
async fn run_in_macos_sandbox(command: Vec<String>, policy: Policy) -> Result<()> {
    info!("Starting macOS sandbox with policy: {}", policy.name);

    // Generate sandbox profile
    let workspace = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(String::from));

    let profile = generate_sandbox_profile(&policy, workspace.as_deref());
    debug!("Generated sandbox profile:\n{}", profile);

    // Write profile to temp file
    let profile_path = write_sandbox_profile(&profile)
        .context("Failed to write sandbox profile")?;

    // Create sandboxed command
    let mut child = create_sandboxed_command(&profile_path, &command)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .context("Failed to spawn sandboxed process")?;

    let mut child_stdin = child.stdin.take().unwrap();
    let child_stdout = child.stdout.take().unwrap();

    let validator = Validator::new(policy.clone());
    let filter = ResponseFilter::new();

    // Proxy stdin -> child with validation
    let stdin_validator = validator.clone();
    let stdin_handle = tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let mut reader = TokioBufReader::new(stdin);
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    match serde_json::from_str::<JsonRpcRequest>(&line) {
                        Ok(request) => {
                            debug!("Request: {} (id: {:?})", request.method, request.id);

                            if let Err(e) = stdin_validator.validate_request(&request) {
                                error!("Request blocked: {}", e);
                                let error_response = JsonRpcResponse::error(
                                    request.id,
                                    -32001,
                                    format!("MCP Jail policy violation: {}", e),
                                );
                                let error_json = serde_json::to_string(&error_response).unwrap();
                                println!("{}", error_json);
                                continue;
                            }
                        }
                        Err(e) => {
                            debug!("Non-JSON-RPC message: {}", e);
                        }
                    }

                    if let Err(e) = child_stdin.write_all(line.as_bytes()).await {
                        error!("Failed to write to child: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to read stdin: {}", e);
                    break;
                }
            }
        }
    });

    // Proxy child stdout -> stdout with filtering
    let stdout_handle = tokio::spawn(async move {
        let mut reader = TokioBufReader::new(child_stdout);
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    match serde_json::from_str::<serde_json::Value>(&line) {
                        Ok(mut response) => {
                            filter.filter(&mut response);
                            let filtered_json = serde_json::to_string(&response).unwrap();
                            println!("{}", filtered_json);
                        }
                        Err(_) => {
                            print!("{}", line);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to read child stdout: {}", e);
                    break;
                }
            }
        }
    });

    // Wait for child to exit
    let status = child.wait().await?;
    debug!("Sandboxed process exited with: {}", status);

    // Cleanup
    stdin_handle.abort();
    stdout_handle.abort();
    cleanup_profile(&profile_path);

    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("Sandboxed process exited with error: {}", status)
    }
}

/// Fallback: Run MCP server locally with proxy validation only (no container isolation)
async fn run_proxy_only(command: Vec<String>, policy: Policy) -> Result<()> {
    warn!("Running in proxy-only mode - NO CONTAINER ISOLATION");

    let validator = Validator::new(policy.clone());
    let filter = ResponseFilter::new();

    // Spawn the MCP server process locally
    let mut child = tokio::process::Command::new(&command[0])
        .args(&command[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .context("Failed to spawn MCP server")?;

    let mut child_stdin = child.stdin.take().unwrap();
    let child_stdout = child.stdout.take().unwrap();

    // Proxy stdin -> child with validation
    let stdin_validator = validator.clone();
    let stdin_handle = tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let mut reader = TokioBufReader::new(stdin);
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // EOF
                Ok(_) => {
                    // Parse and validate request
                    match serde_json::from_str::<JsonRpcRequest>(&line) {
                        Ok(request) => {
                            debug!("Request: {} (id: {:?})", request.method, request.id);

                            // Validate against policy
                            if let Err(e) = stdin_validator.validate_request(&request) {
                                error!("Request blocked: {}", e);

                                // Send error response
                                let error_response = JsonRpcResponse::error(
                                    request.id,
                                    -32001,
                                    format!("MCP Jail policy violation: {}", e),
                                );
                                let error_json = serde_json::to_string(&error_response).unwrap();
                                println!("{}", error_json);
                                continue;
                            }
                        }
                        Err(e) => {
                            debug!("Non-JSON-RPC message: {}", e);
                        }
                    }

                    // Forward to child
                    if let Err(e) = child_stdin.write_all(line.as_bytes()).await {
                        error!("Failed to write to child: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to read stdin: {}", e);
                    break;
                }
            }
        }
    });

    // Proxy child stdout -> stdout with filtering
    let stdout_handle = tokio::spawn(async move {
        let mut reader = TokioBufReader::new(child_stdout);
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // EOF
                Ok(_) => {
                    // Parse and filter response
                    match serde_json::from_str::<serde_json::Value>(&line) {
                        Ok(mut response) => {
                            // Filter sensitive data
                            filter.filter(&mut response);
                            let filtered_json = serde_json::to_string(&response).unwrap();
                            println!("{}", filtered_json);
                        }
                        Err(_) => {
                            // Pass through non-JSON
                            print!("{}", line);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to read child stdout: {}", e);
                    break;
                }
            }
        }
    });

    // Wait for child to exit
    let status = child.wait().await?;
    debug!("MCP server exited with: {}", status);

    // Cancel proxy tasks
    stdin_handle.abort();
    stdout_handle.abort();

    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("MCP server exited with error: {}", status)
    }
}
