const path = require('path');
const webpack = require('webpack')
const HtmlWebpackPlugin = require('html-webpack-plugin');

module.exports = {
  mode: 'development',

  entry: {
      boot: ['@babel/polyfill', path.resolve(__dirname, 'src') + '/boot.js']
  },

  devtool: 'inline-source-map',

  devServer: {
    https: true,
    port: 8443,
    compress: true,
    contentBase: './dist',
    hot: true
  },

  plugins: [
    new webpack.HotModuleReplacementPlugin(),
    new HtmlWebpackPlugin({
      template: './src/index.html',
      filename: './index.html'
   })
  ],

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

  output: {
    filename: '[name]-bundle.js',
    path: path.resolve(__dirname, 'dist')
  }
}
