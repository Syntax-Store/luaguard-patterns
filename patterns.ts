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

  // VEHICLE EXPLOITS
  vehicleExploits: [
    {
      pattern: /SetVehicleEngineOn|SetVehicleDoorOpen/g,
      title: "Vehicle property manipulation",
      description: "Vehicle property changes without validation",
      severity: "medium",
      suggestion: "Verify vehicle ownership and implement cooldowns on vehicle modifications. Example: if IsVehicleOwnedBy(vehicle, source) and CheckCooldown(source) then"
    },
    {
      pattern: /SetVehicleEngineHealth|SetVehicleBodyHealth/g,
      title: "Vehicle health manipulation",
      description: "Vehicle health changes without validation",
      severity: "medium",
      suggestion: "Add server-side health validation and gradual health change checks. Example: if IsHealthChangeValid(currentHealth, newHealth) then"
    }
  ],

  // RESOURCE MANIPULATION
  resourceManipulation: [
    {
      pattern: /StopResource|StartResource|RestartResource/g,
      title: "Resource control manipulation",
      description: "Resource control without proper permissions",
      severity: "critical",
      suggestion: "Restrict resource control to high-level ACE permissions only. Example: if IsPlayerAceAllowed(source, 'command.resources') then"
    },
    {
      pattern: /LoadResourceFile|SaveResourceFile/g,
      title: "Resource file manipulation",
      description: "Resource file access without proper validation",
      severity: "high",
      suggestion: "Implement strict file access controls and path validation. Example: if IsPathSafe(path) and IsFileOperationAllowed(source) then"
    }
  ],

  // EVENT SYSTEM
  eventSystem: [
    {
      pattern: /RegisterNetEvent|RegisterServerEvent/g,
      title: "Unprotected event registration",
      description: "Event registration without proper validation",
      severity: "high",
      suggestion: "Use prefix naming conventions and implement event handlers with proper validation. Example: AddEventHandler('prefix:eventName', function(data) if ValidateEventData(data) then"
    },
    {
      pattern: /TriggerEvent|TriggerServerEvent/g,
      title: "Unprotected event trigger",
      description: "Event triggering without proper validation",
      severity: "high",
      suggestion: "Add rate limiting, data validation, and event logging. Example: if not IsPlayerRateLimited(source) and ValidateEventData(data) then"
    }
  ],

  // ANTI-CHEAT BYPASS
  antiCheatBypass: [
    {
      pattern: /SetEntityVisible|SetEntityAlpha/g,
      title: "Visibility manipulation",
      description: "Entity visibility changes without validation",
      severity: "high",
      suggestion: "Implement server-side visibility verification and periodic checks. Example: CreateThread(function() while true do VerifyEntityVisibility() Wait(1000) end end)"
    },
    {
      pattern: /SetRunSprintMultiplier|SetSwimMultiplier/g,
      title: "Movement speed manipulation",
      description: "Player movement speed changes without validation",
      severity: "high",
      suggestion: "Add speed monitoring and position validation server-side. Example: if not IsPlayerSpeedValid(source, speed) then HandleCheatDetection(source) end"
    }
  ],

  // PERFORMANCE ISSUES
  performanceIssues: [
    {
      pattern: /while\s+true\s+do(?![^{]*Wait\()/g,
      title: "Infinite loop detected",
      description: "Infinite loop without Wait() function",
      severity: "high",
      suggestion: "Always include Wait() in loops and implement loop breaking conditions. Example: while true do -- code here Citizen.Wait(0) if shouldBreak then break end end"
    },
    {
      pattern: /GetActivePlayers|GetGamePool/g,
      title: "Resource intensive operation",
      description: "Performance heavy operation without caching",
      severity: "medium",
      suggestion: "Cache results and implement cooldowns between operations. Example: local cachedPlayers = {} local lastUpdate = 0 -- Update cache periodically"
    }
  ],

  // DEBUGGING AND LOGGING
  debugging: [
    {
      pattern: /print\s*\(|Citizen\.Trace/g,
      title: "Debug output detected",
      description: "Debug output in production code",
      severity: "low",
      suggestion: "Replace with proper logging system. Example: if Config.Debug then exports['logging']:Log(message, level) end"
    }
  ],

  // NUI EXPLOITATION
  nuiExploitation: [
    {
      pattern: /SendNUIMessage|RegisterNUICallback/g,
      title: "Unprotected NUI interaction",
      description: "NUI interaction without proper validation",
      severity: "medium",
      suggestion: "Validate all NUI data and implement request limiting. Example: RegisterNUICallback('action', function(data, cb) if ValidateNUIData(data) then"
    }
  ]
}
