npm init
npm install typescript --save-dev
npm install @types/node@^12 --save-dev
npm install typedoc -save-dev
npm install typedoc-plugin-markdown --save-dev
npm i mocha -D
npm i chai -D
npx tsc --init --rootDir src --outDir lib --esModuleInterop --resolveJsonModule --lib es6,dom  --module commonjs
mkdir lib
mkdir src
mkdir test
touch src/index.ts
touch test/test.js 
