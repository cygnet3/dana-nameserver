use bip353::{Bip353Error, ResolverConfig};
use serde::{Deserialize, Serialize};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json as AxumJson,
    routing::{get, post},
    Json, Router,
};
use reqwest::{Client};
use log::{info, warn, error, debug};
use silentpayments::{Network as SpNetwork, SilentPaymentAddress};
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use bitcoin_payment_instructions::{amount::Amount, dns_resolver::DNSHrnResolver, PaymentInstructions, PaymentMethod, Network};

const CLOUDFLARE_API_BASE_URL: &str = "https://api.cloudflare.com/client/v4";

// Register endpoint types
#[derive(Deserialize, Serialize)]
struct RegisterRequest {
    id: String,
    domain: String,
    user_name: Option<String>,
    sp_address: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    id: String,
    message: String,
    dana_address: Option<String>,
    sp_address: Option<String>,
    dns_record_id: Option<String>,
}

// Lookup endpoint types
#[derive(Deserialize)]
struct LookupRequest {
    sp_address: String,
    id: String,
}

#[derive(Serialize)]
struct LookupResponse {
    id: String,
    message: String,
    dana_address: Vec<String>,
    sp_address: Option<String>,
}

#[derive(Serialize)]
struct CloudflareRequest {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    ttl: u32,
}

async fn fetch_sp_address_from_txt_record(
    user_name: &str,
    domain: &str,
    network: SpNetwork
) -> Result<Option<SilentPaymentAddress>, Bip353Error> {
    debug!("Checking if TXT record exists for user {} on domain {} and network {:?}", user_name, domain, network);
    // Let's not allow regtest address is doesn't make much sense anyway
    let core_network = match network {
        SpNetwork::Mainnet => Network::Bitcoin,
        SpNetwork::Testnet => Network::Testnet,
        SpNetwork::Regtest => return Err(Bip353Error::InvalidAddress("Don't allow for regtest address".to_string()))
    };
    // Basically silent payments doesn't make the distinction between different testnet
    let dns_config = match core_network {
        Network::Bitcoin => ResolverConfig::default(),
        Network::Testnet => ResolverConfig::testnet(),
        _ => unreachable!()
    };
    let socket_addr = dns_config.dns_resolver.clone();
    let resolver = bip353::Bip353Resolver::with_config(dns_config)?;
    let resolved_address = resolver.resolve(user_name, domain).await;
    let payment_instructions = match resolved_address {
        Ok(instructions) => instructions,
        Err(e) => {
            match e {
                Bip353Error::DnsError(_) => return Ok(None), // We can't find a record for this user name
                _ => return Err(e)
            }
        }
    };
    match payment_instructions {
        PaymentInstructions::ConfigurableAmount(instructions) => {
            // The resolver is pretty much useless here since we're only interested in silent payment
            let hrn_resolver = DNSHrnResolver(socket_addr); 
            let dummy_amount = Amount::from_sats(10_000).unwrap(); // Just defining something unlikely to fail in case there's a lnurl in the same entry
            let fixed_amt_instructions = instructions.set_amount(dummy_amount, &hrn_resolver).await?;
            for method in fixed_amt_instructions.methods().iter() {
                match method {
                    PaymentMethod::SilentPayment(sp_address) => {
                        return Ok(Some(sp_address.clone()));
                    },
                    _ => continue
                }
            }
        }
        PaymentInstructions::FixedAmount(instructions) => {
            for method in instructions.methods().iter() {
                match method {
                    PaymentMethod::SilentPayment(sp_address) => {
                        return Ok(Some(sp_address.clone()));
                    },
                    _ => continue
                }
            }
        }
    };

    Ok(None)
}

async fn create_txt_record(
    client: &Client,
    zone_id: &str,
    api_token: &str,
    name: &str,
    content: &str,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("{}/zones/{}/dns_records", CLOUDFLARE_API_BASE_URL, zone_id);
    
    debug!("Creating TXT record: {} -> {}", name, content);
    debug!("Using Cloudflare API URL: {}", url);
    
    let record = CloudflareRequest {
        record_type: "TXT".to_string(),
        name: name.to_string(),
        content: content.to_string(),
        ttl: 3600, // 1 hour TTL
    };

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_token))
        .header("Content-Type", "application/json")
        .json(&record)
        .send()
        .await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        if let Some(id) = result["result"]["id"].as_str() {
            info!("Successfully created TXT record {} with ID: {}", name, id);
            Ok(Some(id.to_string()))
        } else {
            warn!("Cloudflare API returned success but no record ID for {}", name);
            Ok(None)
        }
    } else {
        let error_text = response.text().await?;
        error!("Cloudflare API error for {}: {}", name, error_text);
        Ok(None)
    }
}

#[derive(Debug, Deserialize)]
struct Record {
    id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    content: String,
    // skip other fields
}

#[derive(Debug, Deserialize)]
struct ApiResponse {
    success: bool,
    result: Vec<Record>,
    // skip result_info, errors, messages, ...
}

async fn list_bitcoin_records(
    zone_id: &str,
    api_token: &str,
) -> Result<Vec<Record>, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("{}/zones/{}/dns_records", CLOUDFLARE_API_BASE_URL, zone_id);
    info!("Listing Bitcoin TXT records from Cloudflare API URL: {}", url);
    let client = Client::new();
    let resp = client
        .get(&url)
        .bearer_auth(api_token)
        .query(&[
            ("type", "TXT"),
            ("content.startswith", "bitcoin:"),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<ApiResponse>().await?;

    info!("Received {} Bitcoin TXT records from Cloudflare", resp.result.len());

    let bitcoin_txts: Vec<Record> = resp.result
        .into_iter()
        .filter(|r| r.record_type == "TXT" && r.content.starts_with("bitcoin:"))
        .collect();

    Ok(bitcoin_txts)
}

#[derive(Clone)]
struct AppState {
    zone_id: String,
    api_token: String,
    domain: String,
    sp_to_dana: Arc<RwLock<HashMap<SilentPaymentAddress, Vec<String>>>>,
}

async fn handle_register(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegisterRequest>,
) -> (StatusCode, AxumJson<RegisterResponse>) {
    let dns_record_id;
    
    // Just in case
    if state.zone_id.is_empty() || state.api_token.is_empty() {
        error!("Cloudflare credentials missing, DNS record creation failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                AxumJson(RegisterResponse {
                    id: request.id,
                    message: "Internal server error, please try again later".to_string(),
                    dana_address: None,
                    sp_address: None,
                    dns_record_id: None,
                })
            );
    }

    // If the domain asked by client is not the domain we're registering for, we return a bad request
    if request.domain != state.domain {
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(RegisterResponse {
                    id: request.id,
                    message: format!("Server registers for domain: {}", state.domain),
                    dana_address: None,
                    sp_address: None,
                    dns_record_id: None,
                })
            )
    }

    // Validate SP address
    let sp_address = match silentpayments::SilentPaymentAddress::try_from(request.sp_address.clone()) {
        Ok(sp_address) => {
            debug!("Valid SP address: {}", sp_address);
            sp_address
        }
        Err(e) => {
            error!("Invalid SP address '{}': {}", request.sp_address, e);
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(RegisterResponse {
                    id: request.id,
                    message: format!("Invalid SP address: {}", e),
                    dana_address: None,
                    sp_address: None,
                    dns_record_id: None,
                })
            );
        }
    };

    // We modify the key depending on the network we're on (mainnet vs signet/testnet)
    let network_key = match sp_address.get_network() {
        SpNetwork::Mainnet => "sp",
        SpNetwork::Testnet => "tsp",
        SpNetwork::Regtest => {
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(RegisterResponse {
                    id: request.id,
                    message: format!("Can't register regtest addresses"),
                    dana_address: None,
                    sp_address: None,
                    dns_record_id: None,
                })
            );
        }
    };

    // TODO verify a signature over some message that user must provides with the request

    // if user_name is empty, we generate a random one
    let user_name = match request.user_name {
        Some(user_name) => user_name,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(RegisterResponse {
                    id: request.id,
                    message: format!("User name is required"),
                    dana_address: None,
                    sp_address: None,
                    dns_record_id: None,
                })
            );
        }
    };

    let dana_address = format!("{}@{}", user_name, state.domain);
    let txt_name = format!("{}.user._bitcoin-payment.{}", user_name, state.domain);
    let txt_content = format!("bitcoin:?{}={}", network_key, sp_address.to_string());

    // First check if the record already exists using DNS-over-HTTPS
    match fetch_sp_address_from_txt_record(&user_name, &state.domain, sp_address.get_network()).await {
        Ok(Some(registered_sp_address)) => {
            if registered_sp_address == sp_address {
                // The record already exists and the SP address is the same, we can return the existing record
                return (
                    StatusCode::OK,
                    AxumJson(RegisterResponse {
                        id: request.id,
                        message: "TXT record already exists".to_string(),
                        dana_address: Some(dana_address),
                        sp_address: Some(sp_address.to_string()),
                        dns_record_id: None,
                    })
                );
            }
            error!("TXT record already exists for user name: {}", user_name);
            return (
                StatusCode::CONFLICT,
                AxumJson(RegisterResponse {
                    id: request.id,
                    message: "TXT record already exists".to_string(),
                    dana_address: Some(format!("{}@{}", user_name, state.domain)),
                    sp_address: Some(sp_address.to_string()),
                    dns_record_id: None, // We don't have the Cloudflare record ID from DNS check
                })
            );
        }
        Ok(None) => debug!("Didn't find a sp address for network {:?} and user name {}", sp_address.get_network(), user_name),
        Err(e) => {
            error!("Error checking for existing TXT record for user name {}: {}", user_name, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                AxumJson(RegisterResponse {
                    id: request.id,
                    message: format!("Error checking for existing TXT record: {}", e),
                    dana_address: None,
                    sp_address: None,
                    dns_record_id: None,
                })
            );
        }
    };
    
    info!("Attempting to create TXT record: {}", txt_name);
    let client = Client::new();
    
    dns_record_id = match create_txt_record(&client, &state.zone_id, &state.api_token, &txt_name, &txt_content).await {
        Ok(Some(id)) => {
            info!("Successfully created TXT record: {} -> {}", txt_name, txt_content);
            Some(id)
        }
        Ok(None) => {
            warn!("Failed to create TXT record: No ID returned from Cloudflare for {}", txt_name);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                AxumJson(RegisterResponse {
                    id: request.id,
                    message: "Failed to create DNS record: No ID returned from Cloudflare".to_string(),
                    dana_address: None,
                    sp_address: None,
                    dns_record_id: None,
                })
            );
        }
        Err(e) => {
            error!("Error creating TXT record {}: {}", txt_name, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                AxumJson(RegisterResponse {
                    id: request.id,
                    message: format!("Failed to create DNS record: {}", e),
                    dana_address: None,
                    sp_address: None,
                    dns_record_id: None,
                })
            );
        }
    };

    let response_body = RegisterResponse {
        id: request.id,
        message: "Successfully registered silent payment address".to_string(),
        dana_address: Some(dana_address),
        sp_address: Some(sp_address.to_string()),
        dns_record_id,
    };
    
    debug!("Sending response for record: {}", response_body.dana_address.as_ref().unwrap_or(&"unknown".to_string()));
    (
        StatusCode::OK,
        AxumJson(response_body)
    )
}

/// Lookup Dana address(es) for a given SP address
async fn handle_lookup_sp_address(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LookupRequest>,
) -> (StatusCode, AxumJson<LookupResponse>) {
    debug!("Lookup request received for SP address: {}", query.sp_address);
    
    // Validate SP address
    let sp_address = match SilentPaymentAddress::try_from(query.sp_address.clone()) {
        Ok(sp_address) => {
            debug!("Successfully parsed SP address: {} (network: {:?})", sp_address, sp_address.get_network());
            sp_address
        }
        Err(e) => {
            error!("Invalid SP address '{}': {}", query.sp_address, e);
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(LookupResponse {
                    id: query.id,
                    message: format!("Invalid SP address: {}", e),
                    dana_address: Vec::new(),
                    sp_address: None,
                })
            );
        }
    };

    // Lookup in the map
    debug!("Looking up SP address in cache map...");
    let map = state.sp_to_dana.read().await;
    debug!("Cache map contains {} entries", map.len());
    
    match map.get(&sp_address) {
        Some(dana_addresses) => {
            info!("Found {} Dana address(es) for SP address {}: {:?}", 
                dana_addresses.len(), 
                sp_address, 
                dana_addresses
            );
            (
                StatusCode::OK,
                AxumJson(LookupResponse {
                    id: query.id,
                    message: "Successfully found Dana address(es)".to_string(),
                    dana_address: dana_addresses.clone(),
                    sp_address: Some(sp_address.to_string()),
                })
            )
        }
        None => {
            warn!("SP address {} not found in cache map", sp_address);
            (
                StatusCode::NOT_FOUND,
                AxumJson(LookupResponse {
                    id: query.id,
                    message: "SP address not found".to_string(),
                    dana_address: Vec::new(),
                    sp_address: Some(sp_address.to_string()),
                })
            )
        }
    }
}

#[tokio::main]
async fn main() {
    // Initialize logging with default level of 'info' if RUST_LOG is not set
    // RUST_LOG can still override this (e.g., RUST_LOG=debug cargo run)
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();
    info!("Starting Dana Name Server");

    if let Err(e) = dotenv::dotenv() {
        error!("Could not load .env file: {}", e);
        std::process::exit(1);
    } else {
        info!("Successfully loaded .env file");
    }

    let zone_id = std::env::var("CLOUDFLARE_ZONE_ID").expect("CLOUDFLARE_ZONE_ID environment variable is required");
    let api_token = std::env::var("CLOUDFLARE_API_TOKEN").expect("CLOUDFLARE_API_TOKEN environment variable is required");
    let domain = std::env::var("DOMAIN_NAME").expect("DOMAIN_NAME environment variable is required");
    
    if zone_id.is_empty() || api_token.is_empty() {
        error!("Cloudflare credentials not provided. Can't proceed.");
        error!("Set CLOUDFLARE_ZONE_ID and CLOUDFLARE_API_TOKEN environment variables to enable DNS integration.");
        std::process::exit(1);
    } else {
        info!("Cloudflare credentials loaded successfully");
        debug!("Zone ID: {}", zone_id);
        debug!("API Token: {}...", &api_token[..8.min(api_token.len())]);
    }

    let sp_to_dana: Arc<RwLock<HashMap<SilentPaymentAddress, Vec<String>>>> = Arc::new(RwLock::new(HashMap::new()));
    
    // Populate the map of sp addresses to dana addresses on startup
    info!("Populating SP address to Dana address map from Cloudflare records...");
    match list_bitcoin_records(&zone_id, &api_token).await {
        Ok(records) => {
            info!("Fetched {} Bitcoin TXT records from Cloudflare", records.len());
            let mut map = sp_to_dana.write().await;
            let mut processed_count = 0;
            let mut skipped_count = 0;
            let mut error_count = 0;
            
            for record in records {
                debug!("Processing record: name='{}', content='{}'", record.name, record.content);
                
                // Parse record name: {user_name}.user._bitcoin-payment.{domain}
                // Extract user_name from the name (user_name can contain dots)
                let pattern = ".user._bitcoin-payment.";
                if let Some(pattern_pos) = record.name.find(pattern) {
                    let user_name = &record.name[..pattern_pos];
                    let dana_address = format!("{}@{}", user_name, domain);
                    debug!("Extracted user_name: '{}', Dana address: '{}'", user_name, dana_address);
                    
                    // Parse record content: bitcoin:?{network_key}={sp_address}
                    // Extract SP address from content
                    if let Some(sp_part) = record.content.strip_prefix("bitcoin:?") {
                        debug!("Found bitcoin: prefix, parsing parameters: {}", sp_part);
                        let mut found_sp = false;
                        
                        // Try to find sp= or tsp= parameter
                        for param in sp_part.split('&') {
                            if let Some(sp_addr_str) = param.strip_prefix("sp=") {
                                debug!("Found sp= parameter: {}", sp_addr_str);
                                match SilentPaymentAddress::try_from(sp_addr_str.to_string()) {
                                    Ok(sp_address) => {
                                        let dana_addr = dana_address.clone();
                                        let existing = map.entry(sp_address.clone()).or_insert_with(Vec::new);
                                        existing.push(dana_addr.clone());
                                        info!("Mapped SP address {} to Dana address {} (total mappings for this SP: {})", 
                                            sp_addr_str, 
                                            &dana_address,
                                            existing.len()
                                        );
                                        processed_count += 1;
                                        found_sp = true;
                                        break;
                                    }
                                    Err(e) => {
                                        warn!("Failed to parse SP address '{}' from record '{}': {}", 
                                            sp_addr_str, 
                                            record.name, 
                                            e
                                        );
                                        error_count += 1;
                                    }
                                }
                            } else if let Some(sp_addr_str) = param.strip_prefix("tsp=") {
                                debug!("Found tsp= parameter: {}", sp_addr_str);
                                match SilentPaymentAddress::try_from(sp_addr_str.to_string()) {
                                    Ok(sp_address) => {
                                        let dana_addr = dana_address.clone();
                                        let existing = map.entry(sp_address.clone()).or_insert_with(Vec::new);
                                        existing.push(dana_addr.clone());
                                        info!("Mapped SP address {} to Dana address {} (total mappings for this SP: {})", 
                                            sp_addr_str, 
                                            &dana_address,
                                            existing.len()
                                        );
                                        processed_count += 1;
                                        found_sp = true;
                                        break;
                                    }
                                    Err(e) => {
                                        warn!("Failed to parse SP address '{}' from record '{}': {}", 
                                            sp_addr_str, 
                                            record.name, 
                                            e
                                        );
                                        error_count += 1;
                                    }
                                }
                            }
                        }
                        
                        if !found_sp {
                            debug!("No valid sp= or tsp= parameter found in record '{}'", record.name);
                            skipped_count += 1;
                        }
                    } else {
                        debug!("Record '{}' does not start with 'bitcoin:?' prefix, skipping", record.name);
                        skipped_count += 1;
                    }
                } else {
                    debug!("Record '{}' does not match expected pattern '.user._bitcoin-payment.', skipping", record.name);
                    skipped_count += 1;
                }
            }
            
            info!("Map population complete: {} entries created, {} records processed, {} skipped, {} errors", 
                map.len(), 
                processed_count, 
                skipped_count, 
                error_count
            );
        }
        Err(e) => {
            warn!("Failed to populate SP address map on startup: {}. Continuing without cache.", e);
        }
    }

    let state = Arc::new(AppState {
        zone_id,
        api_token,
        domain,
        sp_to_dana,
    });

    let v1_router = Router::new()
        .route("/register", post(handle_register))
        .route("/lookup", get(handle_lookup_sp_address));

    let app = Router::new()
        .nest("/v1", v1_router)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("Failed to bind to port 8080");
    
    info!("Server starting on http://127.0.0.1:8080");
    info!("API endpoint available at: http://127.0.0.1:8080/v1/register");
    info!("API endpoint available at: http://127.0.0.1:8080/v1/lookup");
    
    axum::serve(listener, app)
        .await
        .expect("Failed to start server");
}

#[cfg(test)]
mod tests {
    use super::*;
    use silentpayments::SilentPaymentAddress;

    #[tokio::test]
    async fn test_check_txt_record_exists_with_address() {
        let address_to_register = SilentPaymentAddress::try_from("sp1qq0cygnetgn3rz2kla5cp05nj5uetlsrzez0l4p8g7wehf7ldr93lcqadw65upymwzvp5ed38l8ur2rznd6934xh95msevwrdwtrpk372hyz4vr6g").unwrap();
        let result = fetch_sp_address_from_txt_record("donate", "danawallet.app", address_to_register.get_network()).await;

        assert!(result.is_ok()); 

        assert_eq!(result.unwrap(), Some(address_to_register));
    }

    #[tokio::test]
    async fn test_check_txt_record_exists_with_no_address() {
        let result = fetch_sp_address_from_txt_record("matt", "mattcorallo.com", silentpayments::Network::Mainnet).await;

        assert!(result.is_ok()); 

        assert_eq!(result.unwrap(), None);
    }
    
    
    #[tokio::test]
    async fn test_check_no_txt_record() {
        let result = fetch_sp_address_from_txt_record("unknown", "danawallet.app", silentpayments::Network::Mainnet).await;

        assert!(result.is_err()); 
    }
}
