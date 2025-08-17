import { MessageType } from "./enums.js"

function message(type, data) {
  return { type: type, data: data }
}

export function ClientHello() { return message(MessageType.ClientHello, null) }
export function Setup(data) { return message(MessageType.Setup, data) }
export function Ot(stage, data) { return message(MessageType.Ot, { stage: stage, data: data }) }
export function Commit(data) { return message(MessageType.Commit, data) }
export function EndGame(data) { return message(MessageType.EndGame, data) }