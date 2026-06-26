'use strict';

var call_builder = require('./call_builder.js');

class FriendbotBuilder extends call_builder.CallBuilder {
  constructor(serverUrl, httpClient, address) {
    super(serverUrl, httpClient);
    this.setPath("friendbot");
    this.url.searchParams.set("addr", address);
  }
}

exports.FriendbotBuilder = FriendbotBuilder;
//# sourceMappingURL=friendbot_builder.js.map
