const fs = require('fs')
const path = require('path')

// Find all .sol files in src/engine
function findSolFiles(dir) {
  let results = []
  const list = fs.readdirSync(dir)
  list.forEach((file) => {
    const filePath = path.join(dir, file)
    const stat = fs.statSync(filePath)
    if (stat && stat.isDirectory()) {
      results = results.concat(findSolFiles(filePath))
    } else if (file.endsWith('.sol')) {
      // ...no logging here...
      results.push(filePath)
    }
  })
  return results
}

// For a .sol file, get the corresponding ABI file in out/
function getAbiFile(solFile) {
  // Always use just the contract name for out directory
  const solName = path.basename(solFile, '.sol')
  const abiPath = path.resolve(__dirname, `../../out/${solName}.sol/${solName}.json`)
  // ...no logging here...
  return abiPath
}

// Load and aggregate ABIs
function aggregateAbis(solFiles) {
  const allAbis = []
  solFiles.forEach((solFile) => {
    const abiFile = getAbiFile(solFile)
    if (fs.existsSync(abiFile)) {
      try {
        const content = fs.readFileSync(abiFile, 'utf8')
        const abiJson = JSON.parse(content)
        let entries = []
        if (Array.isArray(abiJson)) {
          entries = abiJson
        } else if (abiJson.abi && Array.isArray(abiJson.abi)) {
          entries = abiJson.abi
        }
        if (entries.length > 0) {
          allAbis.push(...entries)
          console.log(`[aggregateAbis] Aggregated ${entries.length} entries from: ${abiFile}`)
        }
      } catch (err) {
        // Only log parse errors for files that exist
        console.error(`Failed to parse ABI file: ${abiFile}`, err)
      }
    }
  })
  return allAbis
}

// Remove duplicates by method signature
function dedupeAbis(abis) {
  const seen = new Set()
  const result = abis.filter((entry) => {
    const sig = entry.type + ':' + (entry.name || '') + ':' + JSON.stringify(entry.inputs || [])
    if (seen.has(sig)) return false
    seen.add(sig)
    return true
  })
  return result
}

function main() {
  const solDir = path.resolve(__dirname, '../../src/engine')
  const outputFile = path.resolve(__dirname, '../../aggregated-abi.json')
  // ...no logging here...
  const solFiles = findSolFiles(solDir)

  if (solFiles.length === 0) {
    console.log('[main] No Solidity files found in src/engine')
    process.exit(0)
  }

  // ...no logging here...
  const allAbis = aggregateAbis(solFiles)
  const dedupedAbis = dedupeAbis(allAbis)

  fs.writeFileSync(outputFile, JSON.stringify(dedupedAbis, null, 2))
  console.log(`[aggregateAbis] Aggregated ABI written to ${outputFile} (${dedupedAbis.length} entries)`)
}

main()
