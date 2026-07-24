import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildCharacterSets,
  calculatePassphraseEntropy,
  calculatePasswordEntropy,
  generatePassphrase,
  generatePassword,
  parseWordlist,
  secureRandomInt,
  strengthForEntropy,
} from '../docs/generator.mjs';

function sequenceCrypto(values) {
  let index = 0;
  return {
    getRandomValues(target) {
      if (index >= values.length) throw new Error('deterministic random sequence exhausted');
      target[0] = values[index];
      index += 1;
      return target;
    },
  };
}

test('secureRandomInt rejects modulo-biased values before returning an index', () => {
  const cryptoSource = sequenceCrypto([0xffffffff, 17]);
  assert.equal(secureRandomInt(10, cryptoSource), 7);
});

test('buildCharacterSets filters ambiguous and custom excluded characters', () => {
  const sets = buildCharacterSets({
    upper: true,
    lower: true,
    digits: true,
    symbols: false,
    noAmbiguous: true,
    excludeChars: 'Az9',
  });

  assert.equal(sets.length, 3);
  assert.equal(sets[0].includes('A'), false);
  assert.equal(sets[0].includes('O'), false);
  assert.equal(sets[1].includes('z'), false);
  assert.equal(sets[1].includes('l'), false);
  assert.equal(sets[2].includes('9'), false);
  assert.equal(sets[2].includes('0'), false);
  assert.equal(sets[2].includes('1'), false);
});

test('generatePassword uses rejection sampling and includes every selected type', () => {
  const cryptoSource = sequenceCrypto([
    0, 0, 0, 0, // first candidate: all uppercase, rejected
    0, 26, 52, 62, // second candidate: upper, lower, digit, symbol
  ]);

  const result = generatePassword({
    length: 4,
    upper: true,
    lower: true,
    digits: true,
    symbols: true,
  }, cryptoSource);

  assert.match(result.password, /[A-Z]/);
  assert.match(result.password, /[a-z]/);
  assert.match(result.password, /[0-9]/);
  assert.match(result.password, /[^A-Za-z0-9]/);
});

test('calculatePasswordEntropy matches exact inclusion-exclusion sample space', () => {
  const entropy = calculatePasswordEntropy({
    length: 2,
    upper: true,
    lower: true,
    digits: false,
    symbols: false,
  });
  const expectedValidCount = (52 ** 2) - (26 ** 2) - (26 ** 2);
  assert.ok(Math.abs(entropy - Math.log2(expectedValidCount)) < 1e-12);
});

test('password generation rejects invalid type and length configurations', () => {
  assert.throws(
    () => generatePassword({ length: 12, upper: false, lower: false, digits: false, symbols: false }),
    /At least one character type/,
  );
  assert.throws(
    () => generatePassword({ length: 1, upper: true, lower: true, digits: false, symbols: false }),
    /Length too short/,
  );
});

test('parseWordlist accepts unique lowercase ASCII words and rejects unsafe data', () => {
  assert.deepEqual(parseWordlist('alpha\nbeta-ray\ngamma\n', 3), ['alpha', 'beta-ray', 'gamma']);
  assert.throws(() => parseWordlist('alpha\nalpha\n', 2), /duplicate/);
  assert.throws(() => parseWordlist('alpha\nBETA\n', 2), /lowercase ASCII/);
  assert.throws(() => parseWordlist('alpha\nbeta\n', 3), /expected 3 words/);
});

test('generatePassphrase selects words securely and appends a fixed-width number', () => {
  const words = ['alpha', 'bravo', 'charlie'];
  const result = generatePassphrase({
    words,
    wordCount: 2,
    separator: '-',
    capitalize: true,
    addNumber: true,
  }, sequenceCrypto([0, 2, 7]));

  assert.equal(result.passphrase, 'Alpha-Charlie07');
  assert.equal(result.entropy, calculatePassphraseEntropy(2, 3, true));
});

test('generatePassphrase rejects an unvalidated or malformed word pool', () => {
  assert.throws(
    () => generatePassphrase({
      words: ['safe', '<script>'],
      wordCount: 2,
      separator: '-',
      capitalize: false,
      addNumber: false,
    }, sequenceCrypto([0, 1])),
    /lowercase ASCII words/,
  );
  assert.throws(
    () => generatePassphrase({
      words: ['same', 'same'],
      wordCount: 2,
      separator: '-',
      capitalize: false,
      addNumber: false,
    }, sequenceCrypto([0, 1])),
    /duplicate words/,
  );
});

test('strength labels match the FastAPI implementation thresholds', () => {
  assert.equal(strengthForEntropy(24.9), 'Weak');
  assert.equal(strengthForEntropy(25), 'Fair');
  assert.equal(strengthForEntropy(45), 'Good');
  assert.equal(strengthForEntropy(60), 'Strong');
});
