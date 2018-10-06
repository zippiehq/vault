const path = require('path');
const webpack = require('webpack')
const UglifyJsPlugin = require('uglifyjs-webpack-plugin');

module.exports = {
  mode: 'production',

  entry: {
      boot: ['@babel/polyfill', path.resolve(__dirname, 'src') + '/boot.js']
  },

  devtool: 'inline-source-map',

  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: { presets: ['@babel/preset-env'] }
	},
      },
    ],
  },

  optimization: {
    minimize: true,
    minimizer: [new UglifyJsPlugin()]
  },

  output: {
    filename: '[name]-bundle.js',
    path: path.resolve(__dirname, 'dist')
  }
}
