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
    },
    {
      pattern: /GiveWeaponToPed|RemoveWeaponFromPed|SetPedAmmo/g,
      title: "Weapon manipulation",
      description: "Weapon changes without proper validation",
      severity: "high",
      suggestion: "Use server-side weapon management and implement ammo tracking. Example: if IsWeaponAllowed(weaponHash) and CheckAmmoLimit(ammo) then"
    }
  ],
}
