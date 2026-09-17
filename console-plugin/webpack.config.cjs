// AI-Author: Codex (OpenAI model not exposed by runtime)
// Based on openshift/console-plugin-template release-4.16.
const path = require('path');
const { ConsoleRemotePlugin } = require('@openshift-console/dynamic-plugin-sdk-webpack');
module.exports = {
  entry: {},
  context: path.resolve(__dirname, 'src'),
  output: { path: path.resolve(__dirname, 'dist'), clean: true, filename: '[name]-[contenthash].js', chunkFilename: '[name]-[contenthash].js' },
  resolve: { extensions: ['.tsx', '.ts', '.js'] },
  module: { rules: [
    { test: /\.tsx?$/, exclude: /node_modules/, use: 'ts-loader' },
    { test: /\.css$/, use: ['style-loader', 'css-loader'] },
  ] },
  plugins: [new ConsoleRemotePlugin()],
  devtool: false,
};
