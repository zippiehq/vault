const path = require('path');
const UglifyJSPlugin = require('uglifyjs-webpack-plugin');

module.exports = {
  mode: 'development',

  entry: {
    worker: ['babel-polyfill', path.resolve(__dirname, 'worker') + '/worker.js'],
      boot: ['babel-polyfill', path.resolve(__dirname, 'src') + '/boot.js']
  },

/*   plugins: [
    new UglifyJSPlugin()
  ], */

  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: [
          'babel-loader',
        ],
      },
    ],
  },

  output: {
    filename: '[name]-bundle.js',
    path: path.resolve(__dirname, 'dist')
  }
};
