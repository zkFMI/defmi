//! Deterministic MT19937 stream used by every reproducible simulation.
//!
//! A simulator whose results are compared against a published set has to
//! reproduce the stream that produced them. Any other generator gives a
//! statistically equivalent run but changes the paired experiment. Mersenne
//! Twister and the derived distributions are therefore implemented explicitly
//! and pinned by contract vectors.
//!
//! What is implemented is the subset the simulation uses: `random`, `getrandbits`,
//! `randrange`, `randint`, `choice`, `choices`, `sample`, `gauss` and
//! `paretovariate`, including the cached second normal that makes `gauss`
//! stateful.

const N: usize = 624;
const M: usize = 397;
const MATRIX_A: u32 = 0x9908_b0df;
const UPPER_MASK: u32 = 0x8000_0000;
const LOWER_MASK: u32 = 0x7fff_ffff;

pub struct DeterministicRng {
    state: [u32; N],
    index: usize,
    /// `gauss` produces two normals at a time and keeps the second.
    gauss_next: Option<f64>,
}

impl DeterministicRng {
    pub fn new(seed: u64) -> Self {
        let mut rng = DeterministicRng {
            state: [0; N],
            index: N + 1,
            gauss_next: None,
        };
        // Versioned integer seeding uses low-to-high 32-bit words.
        let mut key: Vec<u32> = Vec::new();
        let mut value = seed;
        if value == 0 {
            key.push(0);
        }
        while value > 0 {
            key.push((value & 0xffff_ffff) as u32);
            value >>= 32;
        }
        rng.init_by_array(&key);
        rng
    }

    fn init_genrand(&mut self, s: u32) {
        self.state[0] = s;
        for i in 1..N {
            let previous = self.state[i - 1];
            self.state[i] = 1_812_433_253u32
                .wrapping_mul(previous ^ (previous >> 30))
                .wrapping_add(i as u32);
        }
        self.index = N;
    }

    fn init_by_array(&mut self, key: &[u32]) {
        self.init_genrand(19_650_218);
        let mut i = 1usize;
        let mut j = 0usize;
        let mut k = N.max(key.len());
        while k > 0 {
            let previous = self.state[i - 1];
            self.state[i] = (self.state[i] ^ (previous ^ (previous >> 30)).wrapping_mul(1_664_525))
                .wrapping_add(key[j])
                .wrapping_add(j as u32);
            i += 1;
            j += 1;
            if i >= N {
                self.state[0] = self.state[N - 1];
                i = 1;
            }
            if j >= key.len() {
                j = 0;
            }
            k -= 1;
        }
        let mut k = N - 1;
        while k > 0 {
            let previous = self.state[i - 1];
            self.state[i] = (self.state[i]
                ^ (previous ^ (previous >> 30)).wrapping_mul(1_566_083_941))
            .wrapping_sub(i as u32);
            i += 1;
            if i >= N {
                self.state[0] = self.state[N - 1];
                i = 1;
            }
            k -= 1;
        }
        self.state[0] = 0x8000_0000;
    }

    fn genrand_u32(&mut self) -> u32 {
        if self.index >= N {
            for i in 0..N {
                let y = (self.state[i] & UPPER_MASK) | (self.state[(i + 1) % N] & LOWER_MASK);
                let mut next = self.state[(i + M) % N] ^ (y >> 1);
                if y & 1 != 0 {
                    next ^= MATRIX_A;
                }
                self.state[i] = next;
            }
            self.index = 0;
        }
        let mut y = self.state[self.index];
        self.index += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c_5680;
        y ^= (y << 15) & 0xefc6_0000;
        y ^= y >> 18;
        y
    }

    /// 53 bits of randomness in [0, 1), assembled from two draws.
    pub fn random(&mut self) -> f64 {
        let a = self.genrand_u32() >> 5;
        let b = self.genrand_u32() >> 6;
        (a as f64 * 67_108_864.0 + b as f64) * (1.0 / 9_007_199_254_740_992.0)
    }

    pub fn getrandbits(&mut self, k: u32) -> u64 {
        if k == 0 {
            return 0;
        }
        if k <= 32 {
            return (self.genrand_u32() >> (32 - k)) as u64;
        }
        // Fill words low-to-high and trim the last one.
        let mut out = 0u64;
        let mut shift = 0u32;
        let mut left = k;
        while left > 0 {
            let take = left.min(32);
            let word = if take < 32 {
                self.genrand_u32() >> (32 - take)
            } else {
                self.genrand_u32()
            };
            out |= (word as u64) << shift;
            shift += take;
            left -= take;
        }
        out
    }

    /// Rejection sampling on the bit length; modulo reduction would be biased
    /// and would also desynchronise the stream.
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let k = 64 - n.leading_zeros();
        loop {
            let r = self.getrandbits(k);
            if r < n {
                return r;
            }
        }
    }

    pub fn randrange(&mut self, start: i64, stop: i64) -> i64 {
        start + self.below((stop - start) as u64) as i64
    }

    pub fn randint(&mut self, a: i64, b: i64) -> i64 {
        self.randrange(a, b + 1)
    }

    pub fn choice<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }

    /// Weighted choice with replacement using cumulative-weight bisection.
    pub fn choices(&mut self, weights: &[f64]) -> usize {
        let mut cumulative = Vec::with_capacity(weights.len());
        let mut total = 0.0;
        for w in weights {
            total += w;
            cumulative.push(total);
        }
        let target = self.random() * total;
        // bisect_right over [0, len-1)
        let hi = cumulative.len() - 1;
        let (mut lo, mut hi) = (0usize, hi);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if target < cumulative[mid] {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        lo
    }

    /// Sample without replacement, using a selection set when `k` is small
    /// relative to `n`.
    pub fn sample(&mut self, n: usize, k: usize) -> Vec<usize> {
        use std::collections::HashSet;
        let mut selected: HashSet<u64> = HashSet::new();
        let mut out = Vec::with_capacity(k);
        // Switch to a pool copy when k is a large fraction of n; both branches
        // are fixed because they consume the stream differently.
        let setsize = if k <= 5 {
            21
        } else {
            21 + 4usize.pow((k as f64).ln().ceil() as u32)
        };
        if n <= setsize {
            let mut pool: Vec<usize> = (0..n).collect();
            for i in 0..k {
                let j = self.below((n - i) as u64) as usize;
                out.push(pool[j]);
                pool[j] = pool[n - i - 1];
            }
        } else {
            for _ in 0..k {
                let mut j = self.below(n as u64);
                while selected.contains(&j) {
                    j = self.below(n as u64);
                }
                selected.insert(j);
                out.push(j as usize);
            }
        }
        out
    }

    /// Two normals from one pair of uniforms; the second is cached, which is why
    /// `gauss` is stateful and `normalvariate` is not.
    pub fn gauss(&mut self, mu: f64, sigma: f64) -> f64 {
        let z = match self.gauss_next.take() {
            Some(z) => z,
            None => {
                let x2pi = self.random() * std::f64::consts::TAU;
                let g2rad = (-2.0 * (1.0 - self.random()).ln()).sqrt();
                self.gauss_next = Some(x2pi.sin() * g2rad);
                x2pi.cos() * g2rad
            }
        };
        mu + z * sigma
    }

    pub fn paretovariate(&mut self, alpha: f64) -> f64 {
        let u = 1.0 - self.random();
        u.powf(-1.0 / alpha)
    }

    pub fn uniform(&mut self, a: f64, b: f64) -> f64 {
        a + (b - a) * self.random()
    }
}

impl DeterministicRng {
    /// Fisher--Yates downward using the same unbiased bounded draw as the rest
    /// of this module.
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below((i + 1) as u64) as usize;
            items.swap(i, j);
        }
    }
}
