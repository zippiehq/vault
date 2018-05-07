const path = require('path');
const UglifyJSPlugin = require('uglifyjs-webpack-plugin');

module.exports = {
  entry: './src/index.js',
  mode: 'development',
/*   plugins: [
    new UglifyJSPlugin()
  ], */
/*  module: {
    rules: [
      {
        test: /\.(js|jsx)$/,
        exclude: /node_modules/,
        use: [
          'babel-loader',
        ],
      },
    ],
  }, */
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'dist')
  }
};
