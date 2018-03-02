const path = require('path');
const UglifyJSPlugin = require('uglifyjs-webpack-plugin');

module.exports = {
  entry: './src/index.js',
  mode: 'development',
/*   plugins: [
    new UglifyJSPlugin()
  ], */
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'dist')
  }
};
