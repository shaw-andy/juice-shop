/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Injectable } from '@angular/core'
import { type ChatMessage, type StoredConversation } from '../chatbot/chat.model'

const STORAGE_KEY = 'juiceshop_chat_conversations'
// Replies from these tools contain customer order data or coupon codes that must not outlive the session
const SENSITIVE_TOOLS = new Set(['getOrderById', 'generateCoupon'])

@Injectable({
  providedIn: 'root'
})
export class ConversationStorageService {
  generateId (): string {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    const random8 = Array.from({ length: 8 }, () => chars[Math.floor(Math.random() * chars.length)]).join('')
    return `${Date.now()}_${random8}`
  }

  generateTitle (firstMessage: string): string {
    return firstMessage.length > 50 ? firstMessage.substring(0, 50) + '…' : firstMessage
  }

  getAll (): StoredConversation[] {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return []
    const conversations: StoredConversation[] = JSON.parse(raw)
    return conversations.sort((a, b) => b.updatedAt - a.updatedAt)
  }

  getById (id: string): StoredConversation | undefined {
    return this.getAll().find(c => c.id === id)
  }

  save (conversation: StoredConversation): void {
    conversation = { ...conversation, messages: this.withoutSensitiveReplies(conversation.messages) }
    const all = this.getAll()
    const index = all.findIndex(c => c.id === conversation.id)
    if (index >= 0) {
      all[index] = conversation
    } else {
      all.push(conversation)
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(all))
  }

  delete (id: string): void {
    const all = this.getAll().filter(c => c.id !== id)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(all))
  }

  deleteAll (): void {
    localStorage.removeItem(STORAGE_KEY)
  }

  // Later replies can repeat what an earlier sensitive tool returned, so every assistant turn from then on is dropped
  private withoutSensitiveReplies (messages: ChatMessage[]): ChatMessage[] {
    const firstSensitive = messages.findIndex(m => m.role === 'assistant' && m.tool_calls?.some(t => SENSITIVE_TOOLS.has(t.function?.name)))
    if (firstSensitive < 0) return messages
    return messages.filter((m, i) => i < firstSensitive || m.role === 'user')
  }
}
