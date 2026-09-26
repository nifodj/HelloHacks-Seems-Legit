import test from 'node:test'
import assert from 'node:assert/strict'
import { analyzeMessage } from '../server.js'

const scamExamples = [
  'This is Microsoft Support. We detected a virus on your computer. Call 1-844-555-0134 right away so our technician can remove it before your files are deleted.',
  "Grandma it's me, I'm in jail after an accident and I need bail money right now, please don't tell mom and dad, call this number 555-0142.",
  'I have access to your webcam and recorded you. Pay 0.05 BTC to this wallet or I release the video to all your contacts.',
  "Hey are you at your desk? I need a favor, can you grab a few gift cards for a client, I'll pay you back later. Kind of urgent.",
]

test('behavior-only scam messages are not classified as likely legitimate', () => {
  for (const message of scamExamples) {
    const result = analyzeMessage(message)
    assert.notEqual(result.verdict, 'likely legitimate', message)
    assert.ok(result.signals.length > 0, message)
  }
})

test('strong scam-format matches can raise the verdict without a link', () => {
  const result = analyzeMessage('Our vendor invoice payment instructions have changed. Please use the new bank account immediately and keep the revised details confidential.')
  assert.equal(result.verdict, 'likely scam')
  assert.ok(result.formatMatches.some((match) => match.strength === 'strong'))
})

test('benign reminders, newsletters, and casual messages remain likely legitimate', () => {
  const benignExamples = [
    'Appointment reminder: your dental cleaning is Thursday at 3 PM. Reply if you need to reschedule.',
    'Our monthly newsletter is here with new articles, recipes, and community updates.',
    'Hey, are you free to grab coffee after work? Let me know.',
  ]
  for (const message of benignExamples) {
    assert.equal(analyzeMessage(message).verdict, 'likely legitimate', message)
  }
})

test('legitimate account-security alerts are not flagged by sign-in wording alone', () => {
  const messages = [
    'Security alert: unusual sign-in activity on your account. Review and secure your account: https://outlook.office365.com/mail/security',
    'A new SSH key was added to your account. Please verify your account immediately by reviewing your SSH keys: https://github.com/settings/keys',
    'Your Apple ID was used to sign in on a new device. Please verify your account immediately: https://appleid.apple.com/account',
  ]
  for (const message of messages) {
    assert.notEqual(analyzeMessage(message).verdict, 'suspicious', message)
    assert.notEqual(analyzeMessage(message).verdict, 'likely scam', message)
  }
})

test('sign-in wording is still flagged alongside suspicious destinations', () => {
  const messages = [
    'Please sign in and verify your account: https://paypal-secure-login.example.com',
    'Please verify your account immediately: http://192.0.2.1/login',
    'Please sign in to secure your account: https://bit.ly/account-check',
  ]
  for (const message of messages) {
    assert.notEqual(analyzeMessage(message).verdict, 'likely legitimate', message)
  }
})
