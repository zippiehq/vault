const path = require('path');
const webpack = require('webpack')
const UglifyJsPlugin = require('uglifyjs-webpack-plugin');
const HtmlWebpackPlugin = require('html-webpack-plugin');

module.exports = {
  mode: 'production',

  entry: {
      boot: ['@babel/polyfill', path.resolve(__dirname, 'src') + '/boot.js']
  },

  devtool: 'source-map',

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
    minimizer: [new UglifyJsPlugin({sourceMap: true})]
  },

plugins: [
	new HtmlWebpackPlugin({
	    template: './src/index.html',
            filename: './index.html' 
})
],

  output: {
    filename: '[name]-[chunkhash:4].js',
    path: path.resolve(__dirname, 'dist')
  }
}
