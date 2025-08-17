function createEnum(values) {
  const enumObject = {};
  for (const val of values) {
    enumObject[val] = val;
  }
  return Object.freeze(enumObject);
}

export const MessageType = createEnum(
  ['ClientHello', 'Setup', 'Ot', 'Commit', 'EndGame', 'Close']
);

export const Move = createEnum(
  ['Normal', 'Promote', 'Castle', 'EnPassant']
);