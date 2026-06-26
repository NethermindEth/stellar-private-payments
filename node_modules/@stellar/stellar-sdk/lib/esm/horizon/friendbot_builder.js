import { CallBuilder } from './call_builder.js';

class FriendbotBuilder extends CallBuilder {
  constructor(serverUrl, httpClient, address) {
    super(serverUrl, httpClient);
    this.setPath("friendbot");
    this.url.searchParams.set("addr", address);
  }
}

export { FriendbotBuilder };
//# sourceMappingURL=friendbot_builder.js.map
