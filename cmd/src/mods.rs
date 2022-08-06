use serde_json::{Map, Value};

pub fn image_to_bytes(input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let mut map: Map<String, Value> = serde_json::from_slice(&*input).unwrap();

    let colors: Vec<_> = map
        .remove("in")
        .unwrap()
        .as_array()
        .unwrap()
        .into_iter()
        .flat_map(|e| {
            e.as_array()
                .unwrap()
                .into_iter()
                .map(|ei| ei.as_u64().unwrap() as u8)
        })
        .collect();
    Ok(colors)
}
