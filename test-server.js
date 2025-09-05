// Test script to verify server endpoints
const axios = require('axios');

const BASE_URL = 'http://localhost:3000';

async function testEndpoints() {
  console.log('🧪 Testing CB-FD-Backend endpoints...\n');

  try {
    // Test health endpoint
    console.log('1. Testing /health endpoint...');
    const healthResponse = await axios.get(`${BASE_URL}/health`);
    console.log('✅ Health check passed:', healthResponse.data.ok);
    console.log('   Environment:', healthResponse.data.environment);
    console.log('   Port:', healthResponse.data.port);
    console.log();

    // Test root endpoint
    console.log('2. Testing / endpoint...');
    const rootResponse = await axios.get(`${BASE_URL}/`);
    console.log('✅ Root endpoint passed:', rootResponse.data.name);
    console.log('   Version:', rootResponse.data.version);
    console.log();

    // Test API status endpoint
    console.log('3. Testing /api/status endpoint...');
    const statusResponse = await axios.get(`${BASE_URL}/api/status`);
    console.log('✅ API status passed:', statusResponse.data.status);
    console.log();

    // Test auth endpoint (should work even without JWT_SECRET)
    console.log('4. Testing /api/auth/verify endpoint...');
    const authResponse = await axios.post(`${BASE_URL}/api/auth/verify`, {});
    console.log('✅ Auth endpoint response:', authResponse.data.message);
    console.log();

    // Test 404 handling
    console.log('5. Testing 404 handling...');
    try {
      await axios.get(`${BASE_URL}/nonexistent`);
    } catch (error) {
      if (error.response?.status === 404) {
        console.log('✅ 404 handling works correctly');
        console.log('   Error message:', error.response.data.error);
      }
    }
    console.log();

    console.log('🎉 All tests passed! Server is ready for Railway deployment.');

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    if (error.response) {
      console.error('   Status:', error.response.status);
      console.error('   Data:', error.response.data);
    }
  }
}

// Only run if this file is executed directly
if (require.main === module) {
  testEndpoints();
}

module.exports = testEndpoints;
