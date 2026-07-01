use anyhow::Result;
use serde::Serialize;

pub fn emit<T: Serialize + ?Sized>(value: &T, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        print_human(value)?;
    }
    Ok(())
}

pub fn format_token_amount(amount: u128, symbol: &str, decimals: u32) -> String {
    let decimals = decimals as usize;
    if decimals == 0 {
        return format!("{amount} {symbol}");
    }

    let abs = format!("{amount:0>width$}", width = decimals + 1);
    let int_part = &abs[..abs.len() - decimals];
    let frac = abs[abs.len() - decimals..].trim_end_matches('0');
    let formatted = if frac.is_empty() {
        int_part.to_string()
    } else {
        format!("{int_part}.{frac}")
    };
    format!("{formatted} {symbol}")
}

fn print_human<T: Serialize + ?Sized>(value: &T) -> Result<()> {
    let json = serde_json::to_value(value)?;
    match json {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                println!("{key}: {}", format_value(&val));
            }
        }
        other => println!("{}", format_value(&other)),
    }
    Ok(())
}

fn format_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".into(),
        serde_json::Value::Bool(v) => v.to_string(),
        serde_json::Value::Number(v) => v.to_string(),
        serde_json::Value::String(v) => v.clone(),
        serde_json::Value::Array(items) => {
            if items.is_empty() {
                "[]".into()
            } else {
                format!("[{} items]", items.len())
            }
        }
        serde_json::Value::Object(map) => format!("{{{}}}", map.len()),
    }
}

pub fn print_kv(key: &str, value: impl std::fmt::Display) {
    println!("{key}: {value}");
}

pub fn print_section(title: &str) {
    println!("{title}");
}
