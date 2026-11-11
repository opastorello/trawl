import { describe, expect, test } from "bun:test"
import { createHash } from "node:crypto"
import { type AltchaChallenge, buildAltchaPayload, solveAltcha, verifyAltchaSolution } from "../src/solvers/altchaPow"

describe("ALTCHA PoW solver", () => {
  describe("SHA-256 legacy challenge mode", () => {
    test("solves a simple SHA-256 challenge", () => {
      const salt = "test-salt-12345"
      const targetCounter = 42
      const challenge = createHash("sha256").update(`${salt}${targetCounter}`).digest("hex")

      const result = solveAltcha({
        algorithm: "SHA-256",
        salt,
        challenge,
      })

      expect(result).toBeDefined()
      expect(result?.solution.counter).toBe(targetCounter)
      expect(result?.solution.derivedKey).toBe(challenge)
    })

    test("verifies SHA-256 solution", () => {
      const salt = "verify-test"
      const targetCounter = 100
      const challenge = createHash("sha256").update(`${salt}${targetCounter}`).digest("hex")

      const challengeObj: AltchaChallenge = {
        algorithm: "SHA-256",
        salt,
        challenge,
      }

      expect(verifyAltchaSolution(challengeObj, targetCounter)).toBe(true)
      expect(verifyAltchaSolution(challengeObj, targetCounter + 1)).toBe(false)
    })
  })

  describe("PBKDF2 prefix mode", () => {
    test("solves PBKDF2-SHA-256 challenge", () => {
      const salt = "abcd1234abcd1234abcd1234abcd1234"
      const keyPrefix = "00"

      const result = solveAltcha(
        {
          algorithm: "PBKDF2-SHA-256",
          salt,
          keyPrefix,
          cost: 100,
        },
        10000,
      )

      expect(result).toBeDefined()
      expect(result?.solution.derivedKey.startsWith(keyPrefix)).toBe(true)
    })

    test("verifies PBKDF2 solution", () => {
      const salt = "abcd1234abcd1234abcd1234abcd1234"
      const keyPrefix = "0"

      const result = solveAltcha(
        {
          algorithm: "PBKDF2-SHA-256",
          salt,
          keyPrefix,
          cost: 100,
        },
        10000,
      )

      expect(result).toBeDefined()
      if (result) {
        expect(
          verifyAltchaSolution({ algorithm: "PBKDF2-SHA-256", salt, keyPrefix, cost: 100 }, result.solution.counter),
        ).toBe(true)
      }
    })
  })

  describe("Scrypt prefix mode", () => {
    test("solves SCRYPT challenge", () => {
      const salt = "1234567890abcdef1234567890abcdef"
      const keyPrefix = "0"

      const result = solveAltcha(
        {
          algorithm: "SCRYPT",
          salt,
          keyPrefix,
          cost: 1024,
          memoryCost: 1,
          parallelism: 1,
        },
        1000,
      )

      expect(result).toBeDefined()
      expect(result?.solution.derivedKey.startsWith(keyPrefix)).toBe(true)
    })
  })

  describe("algorithm normalization", () => {
    test("handles various algorithm name formats", () => {
      const salt = "test1234567890ab"
      const challenge = createHash("sha256").update(`${salt}1`).digest("hex")

      for (const algo of ["SHA-256", "sha-256", "SHA256", "sha256"]) {
        const result = solveAltcha({
          algorithm: algo as any,
          salt,
          challenge,
        })
        expect(result).toBeDefined()
        expect(result?.solution.counter).toBe(1)
      }
    })

    test("rejects unsupported algorithms", () => {
      const result = solveAltcha({
        algorithm: "UNSUPPORTED" as any,
        salt: "test",
        challenge: "test",
      })
      expect(result).toBeUndefined()
    })
  })

  describe("payload building", () => {
    test("builds correct base64 payload", () => {
      const salt = "payload-test-salt"
      const challenge = createHash("sha256").update(`${salt}5`).digest("hex")

      const result = solveAltcha({
        algorithm: "SHA-256",
        salt,
        challenge,
      })

      expect(result).toBeDefined()
      if (result) {
        const payload = buildAltchaPayload(result)
        expect(typeof payload).toBe("string")
        const decoded = JSON.parse(atob(payload))
        expect(decoded.solution).toBe(5)
      }
    })
  })

  describe("performance", () => {
    test("solves within reasonable time", () => {
      const salt = "perf-test-12345678901234567890"
      const challenge = createHash("sha256").update(`${salt}500`).digest("hex")

      const start = Date.now()
      const result = solveAltcha({
        algorithm: "SHA-256",
        salt,
        challenge,
      })
      const elapsed = Date.now() - start

      expect(result).toBeDefined()
      expect(result?.solution.counter).toBe(500)
      expect(elapsed).toBeLessThan(1000)
    })
  })

  describe("edge cases", () => {
    test("returns undefined when max iterations exceeded", () => {
      const result = solveAltcha(
        {
          algorithm: "SHA-256",
          salt: "impossible",
          challenge: "0000000000000000000000000000000000000000000000000000000000000000",
        },
        10,
      )
      expect(result).toBeUndefined()
    })

    test("handles empty keyPrefix", () => {
      const result = solveAltcha({
        algorithm: "PBKDF2-SHA-256",
        salt: "test1234567890ab",
        keyPrefix: "",
        cost: 100,
      })
      expect(result).toBeUndefined()
    })
  })
})
