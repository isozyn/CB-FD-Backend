const FormData = require('form-data');
const fs = require('fs');
const axios = require('axios');

async function testFileUpload() {
  try {
    const form = new FormData();
    form.append('file', fs.createReadStream('test.txt'));
    
    console.log('Testing file upload endpoint...');
    const response = await axios.post('http://localhost:5000/analyze/file', form, {
      headers: {
        ...form.getHeaders(),
      },
    });
    
    console.log('Success:', response.data);
  } catch (error) {
    console.error('Error:', error.response?.data || error.message);
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Headers:', error.response.headers);
    }
  }
}

testFileUpload();
