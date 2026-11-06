/*
 * The pure core modules (graph-core, loader, exports, catalog) and the vendored JSZip, typed. They are the
 * same UMD files the node:test suites require(); vite.config.ts (`ae-umd`) turns them into ES modules here.
 */
import catalog from './catalog.js';
import exportsApi from './exports.js';
import graphCore from './graph-core.js';
import loader from './loader.js';
import JSZip from '../../vendor/jszip.min.js';

export const C = graphCore;
export const L = loader;
export const X = exportsApi;
export const K = catalog;
export { JSZip };
export type * from './types';
