import { SecurityPattern } from "@/types/security"

export const SECURITY_PATTERNS: Record<string, SecurityPattern[]> = {
  // PLAYER EXPLOITS
  playerExploits: [
    {
      pattern: /SetPlayerModel|GetHashKey|RequestModel/g,
      title: "Player model manipulation",
      description: "Player model changes without validation",
      severity: "medium",
      suggestion: "Create a whitelist of allowed models and validate model changes server-side. Example: if Config.AllowedModels[modelHash] then"
    },
    {
      pattern: /SetPlayerInvincible|SetPlayerControl/g,
      title: "Player state manipulation",
      description: "Player state changes without server validation",
      severity: "high",
      suggestion: "Move state changes server-side and implement periodic state verification checks"
    }
  ],

  // NETWORK EXPLOITS
  networkExploits: [
    {
      pattern: /TriggerServerEvent|TriggerEvent/g,
      title: "Unprotected event triggers",
      description: "Events being triggered without rate limiting or validation",
      severity: "critical",
      suggestion: "Implement rate limiting and add validation checks for event parameters"
    }
  ],

  // RESOURCE EXPLOITS
  resourceExploits: [
    {
      pattern: /LoadResourceFile|SaveResourceFile/g,
      title: "Resource file manipulation",
      description: "Direct resource file access without proper validation",
      severity: "high",
      suggestion: "Restrict file operations to specific directories and validate file paths"
    }
  ],

  // EVENT HANDLING
  eventHandling: [
    {
      pattern: /RegisterNetEvent.*\(["'].*["']\)/g,
      title: "Insecure event registration",
      description: "Network event registered without proper handler validation",
      severity: "medium",
      suggestion: "Add source validation and parameter checking in event handlers"
    }
  ],

  // Add your custom categories and patterns below
  customPatterns: [
    {
      pattern: /YourCustomPattern/g,
      title: "Custom security check",
      description: "Description of what this pattern checks for",
      severity: "low",
      suggestion: "How to fix or prevent this security issue"
    }
  ]
}
