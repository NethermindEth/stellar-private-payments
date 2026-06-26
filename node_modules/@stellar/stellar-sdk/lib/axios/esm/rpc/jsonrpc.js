function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}
async function postObject(client, url, method, param = null) {
  const response = await client.post(url, {
    jsonrpc: "2.0",
    // TODO: Generate a unique request id
    id: 1,
    method,
    params: param
  });
  if (hasOwnProperty(response.data, "error")) {
    throw response.data.error;
  } else {
    return response.data?.result;
  }
}

export { postObject };
//# sourceMappingURL=jsonrpc.js.map
