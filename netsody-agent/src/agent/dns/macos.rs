use std::net::Ipv4Addr;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::io::BufWriter;
use tokio::process::Command;
use tracing::trace;

const SCUTIL_DNS_KEY: &str = "/Network/Service/Netsody/DNS";

/// Adds DNS configuration using scutil (macOS).
///
/// # Arguments
/// * `dns_ip` - The DNS server IP address
/// * `domains` - List of domains to add as supplemental match domains
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` with error message on failure
pub(crate) async fn scutil_add(dns_ip: &Ipv4Addr, domains: &[&str]) -> Result<(), String> {
    trace!(
        "Adding DNS configuration with scutil: IP={}, domains={:?}",
        dns_ip, domains
    );

    let mut child = Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn scutil: {e}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or("Failed to open stdin for scutil".to_string())?;

    let mut writer = BufWriter::new(&mut stdin);

    // Build scutil script
    let mut script = String::new();
    script.push_str("d.init\n");
    script.push_str(&format!("d.add ServerAddresses * {}\n", dns_ip));
    script.push_str(&format!(
        "d.add SupplementalMatchDomains * {}\n",
        domains.join(" ")
    ));
    script.push_str("d.add SupplementalMatchDomainsNoSearch 0\n");
    script.push_str(&format!("set State:{}\n", SCUTIL_DNS_KEY));
    script.push_str("quit\n");

    writer
        .write_all(script.as_bytes())
        .await
        .map_err(|e| format!("Failed to write to scutil stdin: {e}"))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("Failed to flush scutil stdin: {e}"))?;
    drop(writer); // Close stdin so scutil can process input

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("Failed to wait for scutil: {e}"))?;

    if output.status.success() {
        trace!("scutil completed successfully.");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "scutil failed with status {}: {}",
            output.status, stderr
        ))
    }
}

/// Removes DNS configuration using scutil (macOS).
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` with error message on failure
pub(crate) async fn scutil_exists() -> Result<bool, String> {
    trace!("Checking if DNS configuration exists with scutil");

    let mut child = Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn scutil: {e}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or("Failed to open stdin for scutil".to_string())?;

    let mut writer = BufWriter::new(&mut stdin);

    let script = format!("show State:{}\nquit\n", SCUTIL_DNS_KEY);

    writer
        .write_all(script.as_bytes())
        .await
        .map_err(|e| format!("Failed to write to scutil stdin: {e}"))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("Failed to flush scutil stdin: {e}"))?;

    drop(writer);
    drop(stdin);

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("Failed to wait for scutil: {e}"))?;

    // Check if the key exists by examining the output content
    // scutil returns "No such key" when the key doesn't exist
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let key_exists =
        output.status.success() && !stdout_str.is_empty() && !stdout_str.contains("No such key");

    Ok(key_exists)
}

pub(crate) async fn scutil_remove() -> Result<(), String> {
    trace!("Removing DNS configuration with scutil");

    let mut child = Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn scutil: {e}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or("Failed to open stdin for scutil".to_string())?;

    let mut writer = BufWriter::new(&mut stdin);

    let script = format!("remove State:{}\nquit\n", SCUTIL_DNS_KEY);

    writer
        .write_all(script.as_bytes())
        .await
        .map_err(|e| format!("Failed to write to scutil stdin: {e}"))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("Failed to flush scutil stdin: {e}"))?;
    drop(writer); // important: close stdin so scutil can process input

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("Failed to wait for scutil: {e}"))?;

    if output.status.success() {
        trace!("scutil remove completed successfully.");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "scutil remove failed with status {}: {}",
            output.status, stderr
        ))
    }
}
