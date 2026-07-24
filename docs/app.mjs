import {
  calculatePasswordEntropy,
  generatePassphrase,
  generatePassword,
  parseWordlist,
  strengthForEntropy,
} from './generator.mjs';

const form = document.getElementById('generator-form');
const tabs = Array.from(document.querySelectorAll('[role="tab"]'));
const modeInput = form.elements.mode;
const randomPanel = document.getElementById('random-panel');
const passphrasePanel = document.getElementById('passphrase-panel');
const lengthInput = document.getElementById('length');
const lengthValue = document.getElementById('length-value');
const generateButton = document.getElementById('generate-button');
const buttonLabel = generateButton.querySelector('span');
const errorMessage = document.getElementById('error-message');
const emptyState = document.getElementById('empty-state');
const results = document.getElementById('results');
const generationStatus = document.getElementById('generation-status');
const clearButton = document.getElementById('clear-button');
const wordlistStatus = document.getElementById('wordlist-status');
let wordlistPromise;

lengthInput.addEventListener('input', () => {
  lengthValue.value = lengthInput.value;
  lengthValue.textContent = lengthInput.value;
});

function clearError() {
  errorMessage.hidden = true;
  errorMessage.textContent = '';
}

function showError(message) {
  errorMessage.textContent = message;
  errorMessage.hidden = false;
  errorMessage.focus();
}

function selectMode(mode, moveFocus = false) {
  modeInput.value = mode;
  const randomActive = mode === 'random';
  tabs.forEach((tab) => {
    const active = tab.dataset.mode === mode;
    tab.setAttribute('aria-selected', String(active));
    tab.tabIndex = active ? 0 : -1;
    if (active && moveFocus) tab.focus();
  });
  randomPanel.hidden = !randomActive;
  passphrasePanel.hidden = randomActive;
  randomPanel.querySelectorAll('input, select').forEach((control) => { control.disabled = !randomActive; });
  passphrasePanel.querySelectorAll('input, select').forEach((control) => { control.disabled = randomActive; });
  buttonLabel.textContent = randomActive ? 'Generate password' : 'Generate passphrase';
  clearError();
}

selectMode(modeInput.value);

tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => selectMode(tab.dataset.mode));
  tab.addEventListener('keydown', (event) => {
    let nextIndex = null;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') nextIndex = (index + 1) % tabs.length;
    if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') nextIndex = (index - 1 + tabs.length) % tabs.length;
    if (event.key === 'Home') nextIndex = 0;
    if (event.key === 'End') nextIndex = tabs.length - 1;
    if (nextIndex !== null) {
      event.preventDefault();
      selectMode(tabs[nextIndex].dataset.mode, true);
    }
  });
});

async function loadWordlist() {
  if (!wordlistPromise) {
    wordlistStatus.textContent = 'Loading and validating the EFF wordlist…';
    wordlistPromise = fetch('./eff_large_wordlist.txt', { cache: 'force-cache', credentials: 'same-origin' })
      .then((response) => {
        if (!response.ok) throw new Error('The passphrase wordlist could not be loaded.');
        return response.text();
      })
      .then((text) => parseWordlist(text, 7776))
      .then((words) => {
        wordlistStatus.textContent = 'EFF long wordlist · 7,776 validated unique words';
        return words;
      })
      .catch((error) => {
        wordlistPromise = undefined;
        wordlistStatus.textContent = 'EFF wordlist unavailable';
        throw error;
      });
  }
  return wordlistPromise;
}

function integerValue(name, minimum, maximum, label) {
  const control = form.elements.namedItem(name);
  const value = Number(control?.value);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} must be between ${minimum} and ${maximum}.`);
  }
  return value;
}

function randomOptions() {
  return {
    length: integerValue('length', 6, 64, 'Password length'),
    upper: form.elements.upper.checked,
    lower: form.elements.lower.checked,
    digits: form.elements.digits.checked,
    symbols: form.elements.symbols.checked,
    noAmbiguous: form.elements.no_ambiguous.checked,
    excludeChars: form.elements.exclude_chars.value,
  };
}

function randomResults(count) {
  const options = randomOptions();
  const entropy = calculatePasswordEntropy(options);
  return Array.from({ length: count }, () => ({
    value: generatePassword(options).password,
    entropy,
    strength: strengthForEntropy(entropy),
  }));
}

async function passphraseResults(count) {
  const words = await loadWordlist();
  const options = {
    words,
    wordCount: integerValue('word_count', 2, 10, 'Word count'),
    separator: form.elements.separator.value,
    capitalize: form.elements.capitalize.checked,
    addNumber: form.elements.add_number.checked,
  };
  return Array.from({ length: count }, () => {
    const generated = generatePassphrase(options);
    return {
      value: generated.passphrase,
      entropy: generated.entropy,
      strength: strengthForEntropy(generated.entropy),
    };
  });
}

function strengthSegments(strength) {
  const activeCounts = { Strong: 4, Good: 3, Fair: 2, Weak: 1 };
  const track = document.createElement('span');
  track.className = 'strength-track';
  track.setAttribute('aria-label', `${strength} strength`);
  for (let index = 0; index < 4; index += 1) {
    const segment = document.createElement('span');
    segment.className = `strength-segment strength-${strength.toLowerCase()}`;
    if (index < activeCounts[strength]) segment.classList.add('is-on');
    track.appendChild(segment);
  }
  return track;
}

async function copyCredential(value, copyButton) {
  try {
    await navigator.clipboard.writeText(value);
    copyButton.textContent = 'Copied';
    copyButton.classList.add('copied');
    window.setTimeout(() => {
      copyButton.textContent = 'Copy';
      copyButton.classList.remove('copied');
    }, 1600);
  } catch {
    const credential = copyButton.previousElementSibling;
    const range = document.createRange();
    const selection = window.getSelection();
    range.selectNodeContents(credential);
    selection.removeAllRanges();
    selection.addRange(range);
    showError('Clipboard access was blocked. The credential is selected; copy it manually.');
  }
}

function renderResults(generated) {
  results.replaceChildren();
  emptyState.hidden = generated.length > 0;
  clearButton.hidden = generated.length === 0;

  const heading = document.createElement('h3');
  heading.className = 'results-heading';
  heading.textContent = `${generated.length} generated ${generated.length === 1 ? 'credential' : 'credentials'}`;
  results.appendChild(heading);

  generated.forEach((credential, index) => {
    const item = document.createElement('article');
    item.className = 'result-item';

    const topLine = document.createElement('div');
    topLine.className = 'result-topline';
    const number = document.createElement('span');
    number.className = 'result-number';
    number.textContent = String(index + 1).padStart(2, '0');
    const badge = document.createElement('span');
    badge.className = `badge badge-${credential.strength.toLowerCase()}`;
    badge.textContent = credential.strength;
    topLine.append(number, badge);

    const passwordLine = document.createElement('div');
    passwordLine.className = 'password-line';
    const value = document.createElement('code');
    value.className = 'password-value';
    value.textContent = credential.value;
    const copyButton = document.createElement('button');
    copyButton.className = 'copy-button';
    copyButton.type = 'button';
    copyButton.textContent = 'Copy';
    copyButton.setAttribute('aria-label', `Copy generated credential ${index + 1}`);
    copyButton.addEventListener('click', () => copyCredential(credential.value, copyButton));
    passwordLine.append(value, copyButton);

    const meta = document.createElement('div');
    meta.className = 'result-meta';
    const entropy = document.createElement('span');
    entropy.textContent = `${credential.entropy.toFixed(1)} bits entropy`;
    meta.append(entropy, strengthSegments(credential.strength));
    item.append(topLine, passwordLine, meta);
    results.appendChild(item);
  });
  generationStatus.textContent = `${generated.length} ${generated.length === 1 ? 'credential' : 'credentials'} generated.`;
}

clearButton.addEventListener('click', () => {
  results.replaceChildren();
  emptyState.hidden = false;
  clearButton.hidden = true;
  generationStatus.textContent = 'Generated credentials cleared.';
  clearError();
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearError();
  if (!form.reportValidity()) return;

  generateButton.disabled = true;
  buttonLabel.textContent = modeInput.value === 'random' ? 'Generating…' : 'Loading securely…';
  try {
    const count = integerValue('count', 1, 20, 'Count');
    const generated = modeInput.value === 'random'
      ? randomResults(count)
      : await passphraseResults(count);
    renderResults(generated);
  } catch (error) {
    showError(error instanceof Error ? error.message : 'The credential could not be generated.');
  } finally {
    generateButton.disabled = false;
    buttonLabel.textContent = modeInput.value === 'random' ? 'Generate password' : 'Generate passphrase';
  }
});
