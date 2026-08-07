const { execSync } = require('child_process');

console.log("Attempting to publish using OIDC...");
try {
  execSync('npm run release', { 
    stdio: 'inherit',
    shell: true,
    env: { ...process.env, NPM_TOKEN: '', NODE_AUTH_TOKEN: '' }
  });
  console.log("Successfully published via OIDC.");
} catch (error) {
  console.log("OIDC publish failed.");
  console.error(error.message);
  console.log("\n=== OIDC FAILED - Possible Solutions ===");
  console.log("1. Enable npm Trusted Publishing:");
  console.log("   https://www.npmjs.com/package/@restingowlorg/owlsessionguard/settings/access");
  console.log("2. Ensure package exists on npm (create it first if needed)");
  console.log("3. Check GitHub Actions has 'id-token: write' permission\n");
  
  console.log("Checking for fallback token...");
  
  if (process.env.FALLBACK_NPM_TOKEN) {
    console.log("Fallback token found. Attempting to publish using token...");
    console.log("Token prefix:", process.env.FALLBACK_NPM_TOKEN.substring(0, 10) + "...");
    
    // Test token validity first
    try {
      console.log("\nVerifying npm token...");
      execSync('npm whoami --registry=https://registry.npmjs.org/', {
        stdio: 'inherit',
        shell: true,
        env: { ...process.env, NPM_TOKEN: process.env.FALLBACK_NPM_TOKEN, NODE_AUTH_TOKEN: process.env.FALLBACK_NPM_TOKEN }
      });
      console.log("✓ Token is valid\n");
    } catch (whoamiError) {
      console.error("✗ Token validation failed:");
      console.error(whoamiError.message);
      console.error("\n=== TOKEN ISSUES ===");
      console.error("1. Token may be expired - generate new token at:");
      console.error("   https://www.npmjs.com/settings/YOUR_USERNAME/tokens");
      console.error("2. Use 'Automation' token type (not 'Classic')");
      console.error("3. Ensure token has 'publish' permission");
      console.error("4. Old tokens bypassing 2FA are deprecated - generate new token\n");
      process.exit(1);
    }
    
    try {
      execSync('npm run release', { 
        stdio: 'inherit', 
        shell: true,
        env: { ...process.env, NPM_TOKEN: process.env.FALLBACK_NPM_TOKEN, NODE_AUTH_TOKEN: process.env.FALLBACK_NPM_TOKEN }
      });
      console.log("Successfully published via fallback token.");
    } catch (fallbackError) {
      console.error("Fallback publish also failed.");
      console.error(fallbackError.message);
      process.exit(1);
    }
  } else {
    console.error("\n=== NO FALLBACK TOKEN ===");
    console.error("NPM_TOKEN secret not found in GitHub secrets.");
    console.error("\nAdd NPM_TOKEN to GitHub repository secrets:");
    console.error("1. Generate token: https://www.npmjs.com/settings/YOUR_USERNAME/tokens");
    console.error("2. Type: 'Automation'");
    console.error("3. GitHub repo → Settings → Secrets → New repository secret");
    console.error("4. Name: NPM_TOKEN, Value: <your-token>\n");
    process.exit(1);
  }
}
