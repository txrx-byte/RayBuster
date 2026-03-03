import { describe, it, expect } from 'vitest';
import { analyzePhysics } from './heuristics';
import { testCases } from './heuristics.test.data';

describe('Heuristics Engine', () => {
  describe('Physics-Based Analysis', () => {
    const physicsCases = testCases.filter(c => c.description.includes('travel'));

    physicsCases.forEach(testCase => {
      it(testCase.description, () => {
        const result = analyzePhysics(testCase.input);
        expect(result.status).toBe(testCase.expected.status);
        if (testCase.expected.reason) {
          expect(result.reason).toContain(testCase.expected.reason);
        }
      });
    });
  });

  describe('Heuristic Analysis (Headless/Bot Signatures)', () => {
    const heuristicCases = testCases.filter(c => c.description.includes('headless') || c.description.includes('ratio as bot'));

    heuristicCases.forEach(testCase => {
      it(testCase.description, () => {
        const result = analyzePhysics(testCase.input);
        expect(result.status).toBe(testCase.expected.status);
        if (testCase.expected.reason) {
          expect(result.reason).toContain(testCase.expected.reason);
        }
      });
    });
  });

  describe('Latency-Based Analysis', () => {
    const latencyCases = testCases.filter(c => c.description.includes('latency') || c.description.includes('execution'));

    latencyCases.forEach(testCase => {
      it(testCase.description, () => {
        const result = analyzePhysics(testCase.input);
        expect(result.status).toBe(testCase.expected.status);
        if (testCase.expected.reason) {
          expect(result.reason).toContain(testCase.expected.reason);
        }
      });
    });
  });

  describe('Clean Traffic', () => {
    const cleanCases = testCases.filter(c => c.expected.status === 'CLEAN' && !c.description.includes('invalid') && !c.description.includes('travel') && !c.description.includes('missing'));

    cleanCases.forEach(testCase => {
      it(testCase.description, () => {
        const result = analyzePhysics(testCase.input);
        expect(result.status).toBe(testCase.expected.status);
      });
    });
  });

  describe('Input Validation', () => {
    const validationCases = testCases.filter(c => c.description.includes('invalid') || c.description.includes('missing'));

    validationCases.forEach(testCase => {
      it(testCase.description, () => {
        const result = analyzePhysics(testCase.input);
        expect(result.status).toBe(testCase.expected.status);
        if (testCase.expected.reason) {
          expect(result.reason).toContain(testCase.expected.reason);
        }
      });
    });
  });
});
