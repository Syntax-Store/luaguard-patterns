# 🛡️ LuaGuard Security Patterns Guide

A comprehensive guide to creating and maintaining security patterns for LuaGuard.

## 📋 Pattern Structure

Each security pattern in `patterns.ts` must follow this structure:

```typescript
{
  pattern: /your_regex_pattern/g,  // Regular expression to match
  title: "Issue title",            // Short, descriptive title
  description: "Description",      // What the pattern detects
  severity: "critical" | "high" | "medium" | "low",
  suggestion: "How to fix"         // Solution or mitigation
}
```

## 🎯 Example Patterns

### Player Exploits
```typescript
{
  pattern: /SetPlayerModel|GetHashKey|RequestModel/g,
  title: "Player model manipulation",
  description: "Player model changes without validation",
  severity: "medium",
  suggestion: "Create a whitelist of allowed models and validate model changes server-side"
}
```

### Network Exploits
```typescript
{
  pattern: /TriggerServerEvent\(['"].*['"]\)/g,
  title: "Unprotected server event",
  description: "Server event triggered without validation",
  severity: "high",
  suggestion: "Add rate limiting and parameter validation"
}
```

### Resource Exploits
```typescript
{
  pattern: /LoadResourceFile|SaveResourceFile/g,
  title: "Resource file manipulation",
  description: "Direct resource file access without proper validation",
  severity: "high",
  suggestion: "Restrict file operations and validate file paths"
}
```

## 📚 Pattern Categories

### Core Categories
- `playerExploits`: Player-related security issues
  - Model manipulation
  - State changes
  - Weapon handling

- `networkExploits`: Network-related vulnerabilities
  - Event triggers
  - Network messages
  - Synchronization issues

- `resourceExploits`: Resource manipulation issues
  - File operations
  - Resource loading
  - Code execution

- `eventHandling`: Event registration and handling
  - Event registration
  - Handler validation
  - Event security

### Custom Categories
Create your own categories based on specific needs:
```typescript
customPatterns: [
  {
    pattern: /your_pattern/g,
    title: "Custom check",
    description: "What to detect",
    severity: "medium",
    suggestion: "How to fix"
  }
]
```

## ⚠️ Severity Levels

| Level | Description | When to Use |
|-------|-------------|-------------|
| `critical` | Immediate security threat | Remote code execution, authentication bypass |
| `high` | Serious vulnerability | Privilege escalation, data exposure |
| `medium` | Security concern | Input validation issues, potential exploits |
| `low` | Minor issue | Best practice violations, code quality |

## 💡 Pattern Writing Best Practices

### Regular Expressions
1. **Always Use Global Flag**
   ```typescript
   pattern: /yourPattern/g  // Correct
   pattern: /yourPattern/   // Incorrect - missing global flag
   ```

2. **Handle Edge Cases**
   ```typescript
   // Good - handles different quote types
   pattern: /TriggerServerEvent\(['"](.*?)['"]\)/g

   // Better - handles optional whitespace
   pattern: /TriggerServerEvent\s*\(\s*['"](.*?)['"]\s*\)/g
   ```

3. **Avoid False Positives**
   ```typescript
   // Bad - too broad
   pattern: /Execute.*/g

   // Good - specific and targeted
   pattern: /ExecuteCommand\(['"].*['"]\)/g
   ```

### Documentation
1. **Clear Descriptions**
   ```typescript
   // Good
   description: "Unprotected network event that could be spammed by modders"

   // Bad
   description: "Bad event usage"
   ```

2. **Actionable Suggestions**
   ```typescript
   // Good
   suggestion: "Add rate limiting using Config.MaxEvents and validate event parameters"

   // Bad
   suggestion: "Fix the code"
   ```

## 🔧 Testing Patterns

1. **Validation Tests**
   - Test against known vulnerable code
   - Check for false positives
   - Verify severity levels

2. **Edge Cases**
   - Different code formatting
   - Various function call styles
   - Mixed quote types
   - Whitespace variations

3. **Performance**
   - Avoid excessive backtracking
   - Test with large codebases
   - Monitor scan times

## 📈 Pattern Maintenance

1. **Version Control**
   - Document pattern changes
   - Track pattern effectiveness
   - Update based on feedback

2. **Regular Updates**
   - Review patterns monthly
   - Update for new exploits
   - Remove outdated patterns

3. **Community Feedback**
   - Monitor false positives
   - Gather user suggestions
   - Update based on new threats

## 🚫 Common Mistakes

1. **Pattern Issues**
   - Missing global flag
   - Too broad patterns
   - Unescaped special characters

2. **Documentation Issues**
   - Vague descriptions
   - Unhelpful suggestions
   - Missing context

3. **Maintenance Issues**
   - Outdated patterns
   - Duplicate checks
   - Inconsistent severity
