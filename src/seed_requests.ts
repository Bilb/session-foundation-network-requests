export class GetSnodesFromSeedRequest {
  public build() {
    return {
      jsonrpc: '2.0',
      id: '0',
      method: 'get_n_service_nodes',
      params: {
        active_only: true,
        limit: 20,
        fields: {
          public_ip: true,
          storage_port: true,
          pubkey_x25519: true,
          pubkey_ed25519: true,
        },
      },
    };
  }
}
