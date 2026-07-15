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
  console.error(error.message); // Print the actual error
  console.log("Checking for fallback token...");
  
  if (process.env.FALLBACK_NPM_TOKEN) {
    console.log("Fallback token found. Attempting to publish using token...");
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
    console.error("No fallback token provided in secrets. Publishing failed.");
    process.exit(1);
  }
}
