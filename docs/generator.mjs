const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS = '0123456789';
const SYMBOLS = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~';
const AMBIGUOUS = new Set('0O1lI');
const UINT32_RANGE = 0x100000000;

function selectedDefinitions(options) {
  return [
    ['uppercase', UPPERCASE, Boolean(options.upper)],
    ['lowercase', LOWERCASE, Boolean(options.lower)],
    ['digits', DIGITS, Boolean(options.digits)],
    ['symbols', SYMBOLS, Boolean(options.symbols)],
  ].filter(([, , enabled]) => enabled);
}

export function buildCharacterSets(options) {
  const selected = selectedDefinitions(options);
  if (selected.length === 0) {
    throw new Error('At least one character type must be selected');
  }

  const excluded = new Set(options.excludeChars || '');
  return selected.map(([name, characters]) => {
    const filtered = Array.from(characters)
      .filter((character) => !options.noAmbiguous || !AMBIGUOUS.has(character))
      .filter((character) => !excluded.has(character))
      .join('');
    if (!filtered) {
      throw new Error(`Selected ${name} character set is empty after exclusions`);
    }
    return filtered;
  });
}

export function secureRandomInt(maxExclusive, cryptoSource = globalThis.crypto) {
  if (!Number.isSafeInteger(maxExclusive) || maxExclusive < 1 || maxExclusive > UINT32_RANGE) {
    throw new Error('Random upper bound must be an integer from 1 through 2^32');
  }
  if (!cryptoSource || typeof cryptoSource.getRandomValues !== 'function') {
    throw new Error('Secure browser randomness is unavailable');
  }

  const rejectionLimit = Math.floor(UINT32_RANGE / maxExclusive) * maxExclusive;
  const value = new Uint32Array(1);
  do {
    cryptoSource.getRandomValues(value);
  } while (value[0] >= rejectionLimit);
  return value[0] % maxExclusive;
}

function validatePasswordLength(length, characterSets) {
  if (!Number.isInteger(length) || length < 1) {
    throw new Error('Length must be a positive integer');
  }
  if (length < characterSets.length) {
    throw new Error('Length too short for selected character types');
  }
}

export function generatePassword(options, cryptoSource = globalThis.crypto) {
  const characterSets = buildCharacterSets(options);
  validatePasswordLength(options.length, characterSets);
  const pool = characterSets.join('');

  while (true) {
    const password = Array.from(
      { length: options.length },
      () => pool[secureRandomInt(pool.length, cryptoSource)],
    ).join('');
    if (characterSets.every((characters) => Array.from(password).some((character) => characters.includes(character)))) {
      return { password, poolSize: pool.length };
    }
  }
}

function combinations(values, choose, start = 0, current = [], output = []) {
  if (current.length === choose) {
    output.push([...current]);
    return output;
  }
  for (let index = start; index <= values.length - (choose - current.length); index += 1) {
    current.push(values[index]);
    combinations(values, choose, index + 1, current, output);
    current.pop();
  }
  return output;
}

export function calculatePasswordEntropy(options) {
  const characterSets = buildCharacterSets(options);
  validatePasswordLength(options.length, characterSets);
  const poolSize = characterSets.reduce((total, characters) => total + characters.length, 0);
  let validPasswords = 0n;

  for (let missingCount = 0; missingCount <= characterSets.length; missingCount += 1) {
    for (const missingSets of combinations(characterSets, missingCount)) {
      const missingSize = missingSets.reduce((total, characters) => total + characters.length, 0);
      const available = BigInt(poolSize - missingSize);
      const term = available ** BigInt(options.length);
      validPasswords += missingCount % 2 === 0 ? term : -term;
    }
  }
  return Math.log2(Number(validPasswords));
}

function validateWordEntries(words, expectedCount = null) {
  if (!Array.isArray(words) || words.length === 0) {
    throw new Error('Invalid wordlist: at least one word is required');
  }
  if (expectedCount !== null && words.length !== expectedCount) {
    throw new Error(`Invalid wordlist: expected ${expectedCount} words, found ${words.length}`);
  }
  if (new Set(words).size !== words.length) {
    throw new Error('Invalid wordlist: duplicate words found');
  }
  if (words.some((word) => typeof word !== 'string' || word !== word.toLowerCase() || !/^[a-z-]+$/u.test(word) || !/[a-z]/u.test(word))) {
    throw new Error('Invalid wordlist: entries must be lowercase ASCII words');
  }
  return words;
}

export function parseWordlist(text, expectedCount = 7776) {
  const words = text.split(/\r?\n/u).map((line) => line.trim()).filter(Boolean);
  return validateWordEntries(words, expectedCount);
}

export function calculatePassphraseEntropy(wordCount, poolSize, addNumber = false) {
  if (!Number.isInteger(wordCount) || wordCount < 1 || !Number.isInteger(poolSize) || poolSize < 1) {
    throw new Error('Entropy inputs must be positive integers');
  }
  return (wordCount * Math.log2(poolSize)) + (addNumber ? Math.log2(100) : 0);
}

export function generatePassphrase(options, cryptoSource = globalThis.crypto) {
  validateWordEntries(options.words);
  if (!Number.isInteger(options.wordCount) || options.wordCount < 1) {
    throw new Error('Word count must be a positive integer');
  }
  if (!['-', '_', '.', ' '].includes(options.separator)) {
    throw new Error('Separator is not supported');
  }

  const selected = Array.from({ length: options.wordCount }, () => {
    const word = options.words[secureRandomInt(options.words.length, cryptoSource)];
    return options.capitalize ? word[0].toUpperCase() + word.slice(1) : word;
  });
  let passphrase = selected.join(options.separator);
  if (options.addNumber) {
    passphrase += String(secureRandomInt(100, cryptoSource)).padStart(2, '0');
  }
  return {
    passphrase,
    entropy: calculatePassphraseEntropy(options.wordCount, options.words.length, options.addNumber),
  };
}

export function strengthForEntropy(entropy) {
  if (entropy < 25) return 'Weak';
  if (entropy < 45) return 'Fair';
  if (entropy < 60) return 'Good';
  return 'Strong';
}
