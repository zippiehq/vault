const path = require('path');
const webpack = require('webpack')

//const UglifyJSPlugin = require('uglifyjs-webpack-plugin');

module.exports = {
  mode: 'development',

  entry: {
      boot: ['@babel/polyfill', path.resolve(__dirname, 'src') + '/boot.js']
  },

  devtool: 'inline-source-map',

  devServer: {
    https: true,
    port: 8443,
    contentBase: './dist',
    hot: true
  },

  plugins: [
    new webpack.HotModuleReplacementPlugin()
  ],

/*   plugins: [
    new UglifyJSPlugin()
  ], */

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
