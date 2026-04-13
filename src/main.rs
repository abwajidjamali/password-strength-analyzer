use actix_web::{web, App, HttpServer, HttpResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

//  Request / Response Types

#[derive(Deserialize)]
struct AnalyzeRequest {
    password: String,
}

#[derive(Serialize)]
struct AnalyzeResponse {
    password_length: usize,
    score: u8,
    strength: String,
    entropy_bits: f64,
    crack_time_estimate: String,
    character_pool: CharacterPool,
    patterns_detected: Vec<String>,
    suggestions: Vec<String>,
}

#[derive(Serialize)]
struct CharacterPool {
    has_lowercase: bool,
    has_uppercase: bool,
    has_digits: bool,
    has_symbols: bool,
    pool_size: u32,
}

//  Common Patterns

fn common_passwords() -> Vec<&'static str> {
    vec![
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "1234567", "letmein", "trustno1", "dragon",
        "baseball", "iloveyou", "master", "sunshine", "ashley",
        "bailey", "passw0rd", "shadow", "123123", "654321",
        "superman", "qazwsx", "michael", "football", "password1",
    ]
}

fn keyboard_walks() -> Vec<&'static str> {
    vec![
        "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl",
        "zxcvbn", "zxcvbnm", "1234567890", "123456789",
        "qweasdzxc", "poiuytrewq",
    ]
}

//  Entropy Calculation

fn calculate_pool_size(password: &str) -> u32 {
    let mut pool: u32 = 0;
    if password.chars().any(|c| c.is_ascii_lowercase()) { pool += 26; }
    if password.chars().any(|c| c.is_ascii_uppercase()) { pool += 26; }
    if password.chars().any(|c| c.is_ascii_digit())     { pool += 10; }
    if password.chars().any(|c| !c.is_alphanumeric())   { pool += 32; }
    if pool == 0 { pool = 1; }
    pool
}

fn calculate_entropy(password: &str) -> f64 {
    let pool = calculate_pool_size(password) as f64;
    let len  = password.len() as f64;
    len * pool.log2()
}

//  Crack Time Estimate

fn crack_time_estimate(entropy_bits: f64) -> String {
    let combinations: f64 = 2_f64.powf(entropy_bits);
    let guesses_per_sec: f64 = 1e10; // 10 billion / sec
    let seconds = combinations / guesses_per_sec;

    if seconds < 1.0            { return "Instantly".to_string(); }
    if seconds < 60.0           { return format!("{:.0} seconds", seconds); }
    if seconds < 3_600.0        { return format!("{:.0} minutes", seconds / 60.0); }
    if seconds < 86_400.0       { return format!("{:.0} hours",   seconds / 3_600.0); }
    if seconds < 2_592_000.0    { return format!("{:.0} days",    seconds / 86_400.0); }
    if seconds < 31_536_000.0   { return format!("{:.0} months",  seconds / 2_592_000.0); }
    if seconds < 3_153_600_000.0{ return format!("{:.0} years",   seconds / 31_536_000.0); }
    "Very long time".to_string()
}

//  Pattern Detection

fn detect_patterns(password: &str) -> Vec<String> {
    let lower = password.to_lowercase();
    let mut patterns: Vec<String> = Vec::new();

    // 1. Common password
    if common_passwords().iter().any(|&p| lower.contains(p)) {
        patterns.push("Common Password Detected".to_string());
    }

    // 2. Keyboard walk
    if keyboard_walks().iter().any(|&k| lower.contains(k)) {
        patterns.push("Keyboard walk pattern (qwerty)".to_string());
    }

   // 3. Repeated characters
    let bytes = password.as_bytes();
    let max_repeat = bytes.windows(2).filter(|w| w[0] == w[1]).count();
    if max_repeat >= 3 {
        patterns.push("Repeated characters detected".to_string());
    }
 
    // 4. Sequential numbers
    let digit_seq: Vec<u8> = password.chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c as u8 - b'0')
        .collect();
    if digit_seq.len() >= 4 {
        let is_seq = digit_seq.windows(2).all(|w| w[1] == w[0] + 1);
        if is_seq { patterns.push("Sequential number pattern (1234)".to_string()); }
    }
 
    // 5. All same character class only
    if password.chars().all(|c| c.is_ascii_lowercase()) {
        patterns.push("Only lowercase letters".to_string());
    } else if password.chars().all(|c| c.is_ascii_uppercase()) {
        patterns.push("Only uppercase letters".to_string());
    } else if password.chars().all(|c| c.is_ascii_digit()) {
        patterns.push("Only digits".to_string());
    }
 
    // 6. Leet-speak detection (p@ssw0rd)
    let leet_map: HashMap<char, char> = [
        ('@', 'a'), ('3', 'e'), ('1', 'i'), ('0', 'o'),
        ('5', 's'), ('7', 't'), ('4', 'a'), ('$', 's'),
    ].iter().cloned().collect();
 
    let deleet: String = password.chars()
        .map(|c| *leet_map.get(&c).unwrap_or(&c))
        .collect::<String>()
        .to_lowercase();
 
    if deleet != lower && common_passwords().iter().any(|&p| deleet.contains(p)) {
        patterns.push("Leet-speak of a common password".to_string());
    }
 
    // 7. Date-like pattern
    let re_year = regex::Regex::new(r"(19|20)\d{2}").unwrap();
    if re_year.is_match(password) {
        patterns.push("Date/year pattern detected".to_string());
    }
 
    // 8. Short password
    if password.len() < 8 {
        patterns.push("Password is too short (less than 8 characters)".to_string());
    }
 
    patterns
}

//  Score Calculation

fn calculate_score(password: &str, entropy: f64, patterns: &[String]) -> u8 {
    let mut score: i32 = 0;

    // Entropy contribution (max 60 pts)
    let entropy_score = (entropy / 128.0 * 60.0).min(60.0) as i32;
    score += entropy_score;

    // Length bonus (max 20 pts)
    let len = password.len();
    score += match len {
        0..=7   =>  0,
        8..=11  => 10,
        12..=15 => 15,
        _       => 20,
    };

    // Character variety bonus (max 20 pts)
    let cp = calculate_pool_size(password);
    score += match cp {
        0..=25  =>  0,
        26..=35 =>  5,
        36..=57 => 10,
        58..=67 => 15,
        _       => 20,
    };

    // Penalty for each pattern detected
    score -= (patterns.len() as i32) * 10;
    score.clamp(0, 100) as u8
}

fn strength_label(score: u8) -> String {
    match score {
        0..=24  => "Weak".to_string(),
        25..=49 => "Fair".to_string(),
        50..=74 => "Strong".to_string(),
        _       => "Very Strong".to_string(),
    }
}

//  Suggestion Generator 

fn generate_suggestions(password: &str, patterns: &[String]) -> Vec<String> {
    let mut tips: Vec<String> = Vec::new();

    if password.len() < 12 {
        tips.push("Use at least 12 characters for a stronger password.".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        tips.push("Add uppercase letters (A–Z).".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        tips.push("Add lowercase letters (a–z).".to_string());
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        tips.push("Include at least one digit (0–9).".to_string());
    }
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        tips.push("Add special characters (!, @, #, $)".to_string());
    }
    if patterns.iter().any(|p| p.contains("Common")) {
        tips.push("Avoid common words or passwords.".to_string());
    }
    if patterns.iter().any(|p| p.contains("Keyboard")) {
        tips.push("Avoid keyboard patterns like 'qwerty' or 'asdf'.".to_string());
    }
    if patterns.iter().any(|p| p.contains("Sequential")) {
        tips.push("Avoid sequential numbers like '1234'.".to_string());
    }
    if patterns.iter().any(|p| p.contains("Repeated")) {
        tips.push("Avoid repeating the same character multiple times.".to_string());
    }
    if patterns.iter().any(|p| p.contains("Date")) {
        tips.push("Avoid using years or dates in your password.".to_string());
    }
    if tips.is_empty() {
        tips.push("Strong Password!".to_string());
    }
    tips
}

//  Handler

async fn analyze(body: web::Json<AnalyzeRequest>) -> HttpResponse {
    let password = &body.password;

    if password.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Password must not be empty."
        }));
    }
    if password.len() > 256 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Password too long (max 256 characters)."
        }));
    }

    let entropy      = calculate_entropy(password);
    let patterns     = detect_patterns(password);
    let score        = calculate_score(password, entropy, &patterns);
    let suggestions  = generate_suggestions(password, &patterns);
    let pool         = calculate_pool_size(password);
    let crack_time   = crack_time_estimate(entropy);

    let response = AnalyzeResponse {
        password_length: password.len(),
        score,
        strength: strength_label(score),
        entropy_bits: (entropy * 100.0).round() / 100.0,
        crack_time_estimate: crack_time,
        character_pool: CharacterPool {
            has_lowercase: password.chars().any(|c| c.is_ascii_lowercase()),
            has_uppercase: password.chars().any(|c| c.is_ascii_uppercase()),
            has_digits:    password.chars().any(|c| c.is_ascii_digit()),
            has_symbols:   password.chars().any(|c| !c.is_alphanumeric()),
            pool_size: pool,
        },
        patterns_detected: patterns,
        suggestions,
    };

    HttpResponse::Ok().json(response)
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "service": "Password Strength Analyzer API"
    }))
}

//  Main

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Password Strength Analyzer API");
    println!("Running at http://127.0.0.1:8080");


    HttpServer::new(|| {
        App::new()
            .route("/health",  web::get().to(health))
            .route("/analyze", web::post().to(analyze))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}