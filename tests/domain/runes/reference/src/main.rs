use bitcoin::{Transaction, TxOut, Amount, ScriptBuf, absolute::LockTime, transaction::Version};
use ordinals::{Runestone, Artifact};
use std::io::{self, BufRead};
fn main() {
 for line in io::stdin().lock().lines() {
  let scripts: Vec<Vec<u8>> = serde_json::from_str(&line.unwrap()).unwrap();
  let tx = Transaction { version: Version(2), lock_time: LockTime::ZERO, input:vec![], output: scripts.into_iter().map(|s| TxOut { value:Amount::ZERO, script_pubkey:ScriptBuf::from_bytes(s) }).collect() };
  let result = match Runestone::decipher(&tx) {
   None => serde_json::json!({"kind":"absent"}),
   Some(Artifact::Cenotaph(c)) => serde_json::json!({"kind":"cenotaph", "flaw":format!("{:?}", c.flaw)}),
   Some(Artifact::Runestone(r)) => serde_json::json!({"kind":"runestone", "edicts":r.edicts.iter().map(|e| serde_json::json!({"id":e.id.to_string(),"amount":e.amount.to_string(),"output":e.output})).collect::<Vec<_>>(), "pointer":r.pointer, "mint":r.mint.map(|m|m.to_string()),"etching":r.etching.is_some()})
  };
  println!("{}",result);
 }
}
