/*
  CS255 - Winter 2014
  Assignment 1: S/KEY Authentication
  Starter Code Version: 1.0

  SUNet ID #1: grantho
  SUNet ID #2: veni
*/

/* 1. Briefly describe your implementation and its design choices. (e.g. What algorithm did you use? How did you structure your code? Did you do something interesting in \texttt{save}/\texttt{load}? If it's not obvious, justify the space/time used by your implementation.)
   Algorithm
   ===================================
   1. We start by placing a pebble at every power of 2 away from the END of the hash
   chain (pebble1 @ END-1 (2^0)), (pebble2 @ END-2 (2^1), ... (last pebble @ 0 (END - 2^logn))
   2. For each call to advance() [next password], there will be a pebble
   at the next position (we argue this in our time complexity section); so
   we simply fetch the pebble's stored hash value for the return value.
   3. Finally, we relocate this "used" pebble by looking at future
   pebbles and then:
   (a) finding the closest pair of adjacent pebbles that have a gap between
   them (i.e. separated by more than one hash)
   (b) after finding these two "adjacent pebbles", we move our "used"
   pebble to the further of these adjacent pebbles and then hash it until
   it reaches the midpoint between these two adjacent pebbles 
   (the "further" pebble will be the one closer to the START of the hash
   chain (n=0))
   ===================================

   Time Complexity: Amortized O(logn) hashes per call to advance()
   ============================================================
   1. Note that the only calls to hash() are made during pebble
   relocation/repositioning; the next password/return value of advance()
   always hits a pebble that was previously placed there. 
   This is provably true because we always move our pebble to the midpoint 
   of the next two pebbles that have a gap in between them. Thus, if we
   let the current position of advance() be n* and consider any pebble "k"
   positions (hashes) away, our midpoint-gap algorithm needs at most 
   log_2(n* - k) + 1 pebbles to ensure that there will be a pebble at 
   the next call to advance (because after each pebble repositioning, 
   the gap between the next pebble and our next call to advance will
   be halved). Since we start with log_2(n) + 1 pebbles that we constantly 
   keep in-use through repositioning, our repositioning algorithm will always 
   have a pebble ready for the next call to advance().

   2. Thus, we only need to show that our pebble repositioning algorithm
   makes amoritzed O(logn) hashes per call to advance(). 
   Consider the number of times that our pebbles will be "hashed" over
   the lifetime of the S/Key Chain. Since we hash a pebble to the midpoint
   of a gap, an upperbound on the number of hashes is the maximum number
   of midpoint gaps that our hash chain can have (i.e. the number of
   intervals we can bisect over the interval [0,n]). 
   
   Technical note: our algorithm only places pebbles at the midpoint of
   gaps and we never move a pebble unless our call to advance()
   lands onthe pebble. Thus, once a pebble has been placed at a midpoint 
   (bisects an interval), that interval is permanently cut in half and
   another pebble will never be hashed to its original midpoint. 
   Therefore, counting the cumulatove number of bisections/midpoints and
   for our hash chain is an accurate upperbound of the number of hashes 
   our algorithm makes.

   Given that we already have a pebble placed at position {n/2}, the next
   biggest midpoints are n/4 hashes away {0 -> n/4 and n/2 -> 3n/4}...
   technically, we already have one of our initial pebbles at 3n/4,
   but for a genenrous upperbound, we'll conservatively pretend that we
   will need to make n/4 hashes to place a pebble at {3n/4} in order to 
   bisect the interval [n/2,n]. 
   For these 4 intervals of size n/4, we need to bisect them four times
   (cover four midpoints with a pebble); this requires n/8 hashes per
   interval {0 -> n/8, n/4 -> 3n/8, etc.}. Next, these eight intervals of
   size n/8, need to be bisected 8 times (8 midpoints to cover w/
   pebbles)... and so on, until we have n/2 intervals of size 2.
   [aside: this is basically a binary tree with a root node of n/2 hashes 
   and each child node is 1/2 the number of hashes of the parent node].

   Summing all of these hashes together, we get:
   SUM[from k=1 to log_2(n)] of [2^(k-1) * n / 2^k] = 
   SUM[from k=1 to log_2(n)] of [n / 2] = log_2(n) * (n/2) 
   (equivalent to sum of node values of a full binary tree 
   w/ depth log_2(n) where the sum of the node values per level/depth is n/2). 
   This sum is an upperbound on the number of hashes our algorithm uses
   because our initial set of pebbles already covers some of the
   midpoints/interval bisections. 
   
   log_2(n) * (n/2) is O(nlogn) run time complexity. 
   Thus, our algorithm makes O(nlogn) hash calls over the entire 
   lifetime of the hash chain/n calls to advance(). 
   Thus, per call to advance(), we make O(logn) amortized calls to hash(). 
   ============================================================

   + Space is clearly O(logn) because we only place a pebble at a power of 2 positions
   away from the end and we only relocate pebbles (never create additional
   pebbles).
   + We copied the naive_chain's implementation of save/load (nothing interesting).
*/

/* 2. If you were designing an authentication mechanism for a hot new startup that wants to protect its users, how would you decide whether/where to use S/KEY?
   To decide where to use S/KEY (or 2nd factor authentication in general),
   we would way the tradeoffs between convenience and security for our
   startup: Using 2nd factor auth/SKEY will add additional security to the
   authentication process, so for a high value service/information storage
   like online banking or business email/dropbox, we might require 2nd
   factor/SKEY during every login attempt. However, using 2nd factor
   authentication is inconvenient/more work for users; so if our startup
   doesn't have valuable information (e.g. a gaming app like AngryBirds) -
   we might just require that our users 2nd factor auth during login once
   a month on a device that they frequently use (like Stanford's 2nd factor auth system).

   In terms of deciding which OTP system to use (S/KEY vs. something like
   TOTP), we would way the following tradeoffs:

   Disadvantages of SKEY: In systems like TOTP, the storage and runtime is
   O(1) - all we need is a secret key's worth of storage and to compute
   one hash for each OTP. However, with SKey, we need O(logn) storage and
   runtime. Furthermore, we also need to initially compute the entire hash
   chain (which must be very long for us to use for the app's lifetime) -
   this an upfront cost of "n" hashes that client will need to
   compute. Thus, if our startup was an app on a computationally
   constrained device (Google Glasses?), it might be better to use TOTP
   because of the lower overhead.
   Advantages of SKEY: On the other hand, SKEY offers greater security
   against additional threat models that break the security of an OTP
   scheme where the server also keeps the secret key/initial hash
   seed. For example, consider an adversary who stealthily steals the
   secret OTP key of a high value client from the server (either by
   steathily compromising one of the startup's servers or if the company
   is using a server farm and someone taps one of the servers or
   synchronization links [e.g. Google & NSA]). With the secret OTP key,
   the attacker can successfully masquerade as the client/victim if the
   attacker also has the client's password in an auth scheme like
   TOTP. However, since the server does not store the client's secret key
   in SKEY, an attacker that manages to
   compromise the server cannot authenticate as the client because the
   attacker is unable to reverse the hash value to obtain the next
   OTP. Thus, if the startup is worried about the security of its servers
   (e.g. it is storing everything on a shared server farm where data is
   constantly migrated/backed up over questionable links from server to
   server), then using SKEY would be a good security decision.  

   Both TOTP and SKEY have synchronization issues that are easily resolved
   (for TOTP, both the client and server could indicate what time counter
   they're using to ensure they say in sync and similarly with SKey, they
   can include the iteration number the hash is on).

*/

/* 3. (Will not affect your grade:) How long did you spend on this project?
   6
*/

/* 4. (Optional:) Do you have any comments or suggestions for improving the assignment?
   Fun assignment -- super cool result to implement and we really enjoyed
   how the assignment was setup so that we only needed to focus on
   the algorithm (and none of the boilerplate JS).
*/


/********* External Imports and Convenience Functions ********/


"use strict"; // Makes it easier to catch errors.

var sjcl = require("./lib/sjcl");
var hash = sjcl.hash.sha256.hash; // Hashes a string or bitArray to a bitArray.
var is_equal = sjcl.bitArray.equal; // Compares two bitArrays.
var hex = sjcl.codec.hex.fromBits; // Converts a bitArray to a hex string.

var pow2 = Math.pow.bind(this, 2); // Calculates 2 to a given power.
var log2 = function(x) {return Math.log(x) / Math.log(2);} // Calculates log base 2.


/******** Naive Hash Chain Implementation ********/


function naive_chain() {

  var chain = {
    state: null
  };

  chain.initialize = function(num_iterations, seed) {
    chain.state = {
      position: 0,
      num_iterations: num_iterations,
      start: hash(seed)
    }

    var initial = chain.state.start;
    for (var i = 0; i < chain.state.num_iterations; i++) {
      initial = hash(initial);
    }

    return initial;
  }

  chain.advance = function() {
    if (chain.state.position + 1 > chain.state.num_iterations) {
      return null;
    }

    var value = chain.state.start;
    for (var i = 1; i < chain.state.num_iterations - chain.state.position; i++) {
      value = hash(value);
    }
    chain.state.position += 1;
    return value;
  }

  // Returns a string.
  chain.save = function() {
    return JSON.stringify(chain.state);
  }

  // Loads a string.
  chain.load = function(str_data) {
    chain.state = JSON.parse(str_data);
  }

  return chain;
}


/******** Pebble-Based Hash Chain Implementation (Jakobsson's algorithm) ********/


function pebble_chain() {

  var chain = {
    state: null
  };

  // our pebble chain will be an array of pebble structs, where each
  // struct records the pebble position and hash value. pebbles[0] will be
  // the first pebble that we use (i.e. the pebble at the n-1'th hash... 
  // the bigger the pebble index, the farther away it is from the END of
  // the hash chain
  chain.initialize = function(num_iterations, seed) {
    chain.state = {
      // we're 0 indexing, so chain goes from 0 (1 hash) -> n-1 (n hashes)
      position: num_iterations - 1,
      num_iterations: num_iterations,
      start: hash(seed),
      pebbles: new Array()
    }
    var pebble_num = Math.floor(Math.log(num_iterations) / Math.log(2))

    var cur_hash = chain.state.start;
    for (var i = 0; i < chain.state.num_iterations; i++) {
      // place a pebble at positions 0, n/2, (n/2+ n/4), (n/2 + n/4 + n/8), 
      // (n/2  + n/4 + n/8 + n/16), ..., n-2: we place the last pebble at
      // 2^pebble_num spots from the end of the chain (@ position 0)
      // the 2nd to last pebble will be placed 2^(pnum-1) away from end (@ n/2)
      // ... the first pebble will be placed 2^(0)=1 away from the end (@ n-2)
      // (we're 0 indexed, so n-1 is the end/last hash)
      if ((chain.state.num_iterations - (1<<pebble_num)) == i) {
        chain.state.pebbles[pebble_num] = { 'position': i, 'value': cur_hash };
        pebble_num -= 1;
      }

      cur_hash = hash(cur_hash);
    }
    return cur_hash;
  }

  chain.advance = function() {
    if (chain.state.position < 0) {
      return null;
    }

    var ret = chain.state.pebbles[0].value;

    // Reposition the pebble by finding the midpoint of pebble_b and pebble_c
    // where pebble_b and pebble_c are the next two consecutive pebbles
    // that have a "gap in between them (don't already have a pebble b/t them)
    chain.state.pebbles.shift(); // remove the pebble for repositioning
    var base_pebble_idx = -1;
    var target_idx = -1;

    // Loop over the remaining pebbles to find the next pair of adjacent
    // pebbles that have a gap between them (diff > 1) and set the
    // replacement pebble's location to be the gap midpoint
    for (var i = 1; i < chain.state.pebbles.length; i++) {
      if (chain.state.pebbles[i-1].position - chain.state.pebbles[i].position > 1) {
        // bigger index = pebble farther away from END (smaller # of hashes)
	// we stick the replacement pebble here & hash it to the gap midpoint
	base_pebble_idx = i; 
        target_idx = (chain.state.pebbles[i].position + chain.state.pebbles[i-1].position) / 2;
        break;
      }
    }
    
    // if there are gaps that could still use pebbles, hash the
    // replacement pebble until it reaches the mid.pt. of the closest
    // pebble gap
    if ((base_pebble_idx != -1) && (target_idx != -1)) {
      var value = chain.state.pebbles[base_pebble_idx].value;
      for (var i= chain.state.pebbles[base_pebble_idx].position + 1; i <= target_idx; i++) {
        value = hash(value);
      }
      chain.state.pebbles.splice(base_pebble_idx, 0, { 'position': target_idx, 'value': value });
    }

    chain.state.position -= 1;
    return ret;
  }

  // Returns a string.
  chain.save = function() {
    return JSON.stringify(chain.state);
  }

  // Loads a string.
  chain.load = function(str_data) {
    chain.state = JSON.parse(str_data);
  }

  return chain;
}

/********* Export functions for testing. ********/


module.exports.naive_chain = naive_chain;
module.exports.pebble_chain = pebble_chain;


/********* End of Original File ********/

