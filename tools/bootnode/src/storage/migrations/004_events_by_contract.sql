-- Lets a request for some contracts skip the others' events.
CREATE INDEX bootnode_events_deployment_contract_ledger_id_idx
  ON bootnode_events (deployment_id, (payload->>'contractId'), ledger, id);
