Introduction
============

This document summarize how a zero-knowledge confidential transaction
scheme works and how to implement it. A confidential transaction scheme
is a transaction scheme with which the transaction value and the balance
of the sender and receiver are encrypted. The zero-knowledge part means
that outsider can effectively learns nothing about the values, although
he can verify the transaction is not fabricated. The main references are
[Bulletproofs](https://eprint.iacr.org/2017/1066) and
[Zether](https://eprint.iacr.org/2019/191). We use Zether to
homomorphically encrypt the transaction value so that the we can
directly add/subtract ciphertext of the encrypted balance which can then
be decrypted into the correct balance after the transaction. We use
bulletproofs to check the transaction value is valid, i.e. it is a
non-negative number within the range $[0, 2^n)$, and after the
transaction the sender must still have a non-negative balance. The
vanilla bulletproofs do not apply to the scenario of zether as Elgamal
commitments are not fully homomorphic. We need to tweak bulletproofs to
support $\Sigma$-protocols, i.e. interactive proof of the values
commited in Bulletproofs are truly the values involved in zether, whence
we obtain a complete and sound proof of a confidential transaction.

Encryption and Decryption of Balance
====================================

From now no, Let $G$ be a group where the discrete logarithm problem is
assumed to be hard to solve. Let
$g, \overrightarrow{g}=(g_1, g_2, \cdots), h, \overrightarrow{h}=(h_1, h_2, \cdots)$
be base points of $G$ whose logarithm relationship is unclear.

Let $y_1 = sk_1 * g$ (resp. $y_2 = sk_2 * g$) be public key of secret
key $sk_1$ (resp. $sk_2$). Assume the balance of every account is in the
interval $[0, 2^n)$, where $n$ is a small integer like 32. The
ciphertexts obtained from encrypting balance $b_1$ (resp. $b_2$) with
public key $y_1$ (resp. $y_2$) is $c_1 = (b_1 * g + r_1 *y_1, r_1 * g)$
(resp. $c_2 = (b_2 * g + r_2 * y_2, r_2 * g)$), where $r_1$ and $r_2$
are random scalars. This is also called ElGamal Commitment.

Using the usual ElGamal decryption, we can obtain $b_1 * g$ (resp.
$b_2 * g$) from ciphertext $c_1$ (resp. $c_2$), i.e. we calculate
$(b_1 * g + r_1 * y_1) - (sk_1 * r_1 * g)$ which equals $b_1 * g$ by
definition of the public key $y_1 = sk_1 * g$. We then obtain $b_1$
(resp. $b_2$) with brute force. This is feasible as $b_1, b_2$ are small
enough.

Confidential Transfer
=====================

For the same public key $y$, we define the addition/subtraction of two
ciphertexts $c_1 = (b_1 * g + r_1 * y, r_1 * g)$ and
$c_2 = (b_2 * g + r_2 * y, r_2 * g)$ as the multiplication/division in
the group $G^2$, for example define
$c_1 + c_2 = ((b_1 + b_2) * g + (r_1+r_2) * y, (r_1+r_2) * g)$. It is
easy to verify the decryption of the resulting ciphertext is indeed the
addition/subtraction of corresponding balance.

That is to say, the mapping from balance interval to ciphertext
homomorphic, we can do the math on ciphertexts which corresponds exactly
to the math on balances.

We want to make a transaction from account $Y$ to account $\bar{Y}$, we
assume $Y$ initially has balance $b$, he/she wants to transfer $b^\star$
to $\bar{Y}$. In the good old bitcoin world. We need only check, it is
indeed $Y$ made the transaction, and $Y$ didn\'t transfer more than what
he/she has, i.e. $b$.

In the brave new world of cryptopia, we have no way to know what $b$ and
$b^\star$ are, as they are both encrypted.

Proof of knowledge of discrete logarithm
========================================

Let\'s summarize what we need to do.

Suppose $Y$, whose public key is $y$, secret key is $sk$, wants to
transfer $b^\star$ to $\bar{Y}$, whose public key is $\bar{y}$, in the
end, X has only $b^\prime$ left in his/her wallet. Our goal is then to
prove the following statements.

1.  The ciphertext $(C, D)$ of $b^\star$ under public key $y$ and random
    number $r$ is $(b^\star * g + r * y, r * g)$.
2.  The ciphertext $(\bar{C}, D)$ of $b^\star$ under public key
    $\bar{y}$ and random number $r$ is
    $(b^\star * g + r * \bar{y}, r * g)$. Note we also enforce $b^\star$
    is encrypted under the same random number $r$.
3.  $C_{n}, D_{n}$, the amount of money of $Y$ left after the
    transaction is the ElGamal encryption of $b^\prime$ under public key
    $y$, i.e. $C_n = b^\star * g + sk * D_n$ and $sk * g = y$.
4.  Both $b^\star$ and $b^\prime$ are within the range $[0, 2^n)$.

We can make use of Schnorr\'s protocol to prove the first three
statements.

In Schnorr\'s protocol, the prover wants to prove that he knows $x$ such
that $(x, h)$ satisfies relationship $h = x * g$ where $g$ is a known
element of group $G$, and $x$ is hidden. Schnorr\'s protocol. First the
prover randomly choose a scalar $r$ and send $u = r * g$ to the
verifier. The verifier send the randomly chosen challenge $c$ to the
prover. The honest prover send $v = (c * x + r) * g$ to the verifier.
The verifier outputs $ v == c*h + u $.

With little changes, we can extend Schnorr\'s protocol to prove
statements like $C = b^\star * g + r * y$. Now We need only a proof
which proves both $b^\star$ and $b^\prime$ are within the range
$[0, 2^n)$, without ever revealing the actual values. In order to do so,
we will first commit the value, and then prove properties concerning the
commitment.

Pederson Commitment
===================

We now provide another way to hide balance which also allow us prove to
statements about the hidden balance. Given a value $v$ in the message
space, we can commit this value and obtain a output $c$ in the
commitment space. $c$ is called the commitment of $v$.

There are two properties concerning the security of a commitment scheme,
binding and hiding. Informally, a commitment is said to be binding if we
can not find two values whose commitment are equal, a commitment is said
to be hiding is we can not discern two values from each other. If in
addition to this two properties, the commitment scheme is homomorphic,
then we translate statements from message space to commitment space.
This is quite useful for us to prove properties of hidden values.

One of the hiding, binding and homomorphic commitment schemes is
Pederson commitment. The Pederson commitment of
$(b, r) \in (\mathbb{Z}, \mathbb{Z})$ is defined to be the function
$PC: (b, r) \mapsto b*g + r*h$ where $g$ and $h$ are fixed base points,
$r$ is called the blinding factor of $b$. Note that in Pederson
Commitment $h$ is fixed. We can easily verify Pedenson commitment is a
homomorphic commitment scheme, i.e. $\forall b_1, r_1, b_2, r_2$, we
have $PC(b_1+b_2, r_1+r_2) = PC(b_1, r_1) + PC(b_2, r_2)$.

We generalize Pederson Commitment to vectors. Let
$(\overrightarrow{a_L}, \overrightarrow{a_R}) \in (\mathbb{Z}^n, \mathbb{Z}^n)$,
we define the Pederson commitment to be the function
$PC: (\overrightarrow{a_L}, \overrightarrow{a_R}, r) \mapsto \sum a_{L_i} * g_i + \sum a_{R_i} * h_i + rh$
where $h$, $g_i$ and $h_i$ are fixed base points, $r$ is called the
blinding factor of $(\overrightarrow{a_L}, \overrightarrow{a_R})$.

Zen of Range Checking
=====================

Instead of proving $a$ is within the range $[0, 2^n)$ directly. We prove
the following equivalent equation.

$$a - \sum_{i=1}^{n} a_{L_i} \times 2^{i-1} = 0 \text{ (eqn:1)}$$

$$a_{L_i} - 1 - a_{R_i} = 0, \forall i = 1, \cdots, n \text{ (eqn:2)}$$

$$a_{R_i} * a_{L_i} = 0, \forall i = 1, \cdots, n \text{ (eqn:3)}$$

Combining [eqn:2](eqn:2) and [eqn:3](eqn:3), we have
$(a_{L_i} - 1) * a_{L_i} = 0$, i.e. $a_{L_i} = 1$ or $a_{L_i} = 0$.
Together with the first equation, we can see that $a_{L_i}$ is the
binary representation of $a$. As we have only $n$ $a_{L_i}$, $a$ is
indeed within the range $[0, 2^n)$.

Denote $\overrightarrow{y_n}$, or simply $\overrightarrow{y}$ when $n$
is clear, $(1, y, \cdots, y^{n-1})$,
$overrightarrow{a_L} = (a_{L_1}, a_{L_2}, \cdots, a_{L_n})$,
$\overrightarrow{a_R} = (a_{R_1}, a_{R_2}, \cdots, a_{R_n})$. Let $X$,
$Y$ be two vector in $\mathbb{Z}^n$, we denote the Euclid inner product
$X\cdot Y$, the Hermitian product $X \circ Y$.

To verify the second equation, the verifier makes a challenge, a random
scalar $y$, to the prove. The prover proves that,

$$ \sum_{i=1}^{i=n} (a_{L_i} - 1 - a_{R_i}) * y^{i-1} = 0 \text{ (eqn:4)}$$

The left side of the above equation is a polynomial of degree at most
$n-1$, so it has at most $n-1$ roots. $y$ is highly unlikely to be a
root of the polynomial unless all coefficients are zero.

Using the same argument, verifying the following equation is enough for
the third equation.

$$ \sum_{i=1}^{i=n} (a_{L_i} * a_{R_i}) * y^{i-1} = 0 \text{ (eqn:5)}$$

Rewrite equation [eqn:4](eqn:4) as
$(\overrightarrow{a_L} - \overrightarrow{1_n} - \overrightarrow{a_R}) \cdot \overrightarrow{y_n} = 0$,
rewrite equation [eqn:5](eqn:5) as
$(\overrightarrow{a_L}) \cdot (\overrightarrow{a_R} \circ \overrightarrow{y_n}) = 0$,
rewrite [eqn:1](eqn:1) as
$a - \overrightarrow{a_L} \cdot \overrightarrow{2_n} = 0$. Using the
trick as above, we combine this equations to a single equation

$$(\overrightarrow{a_L} - \overrightarrow{1_n} - \overrightarrow{a_R}) \cdot \overrightarrow{y_n} + \overrightarrow{a_L}\cdot (\overrightarrow{a_R} \circ \overrightarrow{y_n}) * z + (a - \overrightarrow{a_L} \cdot \overrightarrow{2_n})* z^2 = 0 \text{ (eqn:6)}$$

This equation is equivalent to

$$(\overrightarrow{a_L} - z\overrightarrow{1_n}) \cdot (\overrightarrow{a_R}\circ \overrightarrow{y_n} + z\overrightarrow{1_n}\circ \overrightarrow{y_n} + z^2 \overrightarrow{2_n}) = z^2 v + \delta(y, z) \text{ (eqn:7)}$$

where
$\delta(y, z) = (z - z^2)(\overrightarrow{1_n} \cdot \overrightarrow{y_n}) - z^3 (\overrightarrow{1_n} \cdot \overrightarrow{2_n})$
is a term involves only $y$ and $z$.

In order to make the range proof zero knowledge, we will add additional
term $\overrightarrow{s_L}x$ (resp. $\overrightarrow{s_R}x$) to
$\overrightarrow{a_L}$ (resp. $\overrightarrow{a_R}$), where
$\overrightarrow{s_L}, \overrightarrow{s_R} \in \mathbb{Z}^n$ are random
vectors, $x$ is unknown variable in $\mathbb{Z}$. Thus the left-hand
side of equation [eqn:7](eqn:7) is now a polynomial in $x$ of degree 2.
Adjust the right-hand side to a polynomial in $x$ of degree 2, Then we
have a equation of the following form

$$\overrightarrow{l(x)} \cdot \overrightarrow{r(x)} = t(x) \text{ (eqn:8)}$$

where

$$\overrightarrow{l(x)} = \overrightarrow{a_L} + \overrightarrow{s_L}x - z\overrightarrow{1_n} \text{ (eqn:9)}$$

$$\overrightarrow{r(x)} = (\overrightarrow{a_R} + \overrightarrow{s_R}x) \circ \overrightarrow{y_n} + z\overrightarrow{1_n}\circ \overrightarrow{y_n} + z^2 \overrightarrow{2_n} \text{ (eqn:10)}$$

$$t(x) = t_0 + t_1 x + t_2 x^2 = z^2 v + \delta(y, z) + t_1 x + t_2 x^2 \text{ (eqn:11)}$$

Range Proof
===========

We now view $x$ as a chosen random scalar. Let $V$ be the Pederson
Commitment of $v$, $T_1$ be the Pederson Commitment of $t_1$, $T_2$ be
the Pederson Commitment of $t_2$,
$A = PC(\overrightarrow{a_L}, \overrightarrow{a_R}, \tilde{a})$,
$S = PC(\overrightarrow{s_L}, \overrightarrow{s_R}, \tilde{s})$,
$P = PC(\overrightarrow{l(x)}, \overrightarrow{r(x)}, \tilde{p})$.

The range proof consists of
$(V, A, S, T_1, T_2, \tilde{t}(x), t(x), \tilde{p})$ and a proof which
proves that $t(x)$ is indeed the inner product of
$\overrightarrow{l(x)}$ and $\overrightarrow{r(x)}$, i.e. [eqn:8](eqn:8)
holds.

To verify [eqn:9](eqn:9) and [eqn:10](eqn:10), we note that knowing the
blinding factor, the Pederson commitment of
$(\overrightarrow{a_L} + \overrightarrow{s_L}x - z\overrightarrow{1_n}, (\overrightarrow{a_R} + \overrightarrow{s_R}x) \circ \overrightarrow{y_n} + z\overrightarrow{1_n}\circ \overrightarrow{y_n} + z^2 \overrightarrow{2_n})$
can be calculated from $A, S$. Given the blinding factor of the Pedenson
commitment of $\overrightarrow{l(x)}, \overrightarrow{r(x)}$, we can
calculate the commitment of
$(\overrightarrow{l(x)}, \overrightarrow{r(x)})$ in the inner product
proof. Thus we can only verify the given inner product proof with the
commitment calculated from above.

To verify [eqn:11](eqn:11), we compare the commitment of $t(x)$ with the
commitment of $z^2 v + \delta(y, z) + t_1 x + t_2 x^2$. The first term
can be calculated directly with $\tilde{t}(x), t(x)$, and the second
term can be calculated with $V, T_1, T_2$.

Aggregated Range Proof
======================

In our use case, we want to aggregate two range proofs. To aggregate
range proofs of terms $a^{(k)}, k = 1, \cdots, m$ are within the range
$[0, 2^n)$, we have the following equations

$$ a^{(k)} - \sum_{i=1}^{n} a^{(k)}_{L_i} \times 2^{i-1} = 0, \forall k = 1, \cdots, m \text{ (eqn:12)}$$

$$a^{(k)}_{L_i} - 1 - a^{(k)}_{R_i} = 0, \forall i = 1, \cdots, n, \forall k = 1, \cdots, m \text{ (eqn:13)}$$

$$a^{(k)}_{R_i} * a^{(k)}_{L_i} = 0, \forall i = 1, \cdots, n, \forall k = 1, \cdots, m \text{ (eqn:14)}$$

Note when we concatenate all the binary representation of
$\overrightarrow{a^{(k)}_{L}}$ (resp. $\overrightarrow{a^{(k)}_{R}}$)
into $\overrightarrow{a_{L}}$ (resp. $\overrightarrow{a_{R}}$), we can
condense [eqn:13](eqn:13) (resp. [eqn:14](eqn:14)) into the
[eqn:2](eqn:2) (resp. [eqn:3](eqn:3)). We use the same trick as before
to compress equations in [eqn:12](eqn:12), then we have
$$(\overrightarrow{a_L} - \overrightarrow{1_{mn}} - \overrightarrow{a_R}) \cdot \overrightarrow{y_{mn}} + \overrightarrow{a_L}\cdot (\overrightarrow{a_R} \circ \overrightarrow{y_{mn}}) * z + \sum_k(a^{(k)} - \overrightarrow{a^{(k)}_{L}} \cdot \overrightarrow{2_n}) * z^{2+k} = 0$$

Accordingly, we adjust terms in [eqn:9](eqn:9), [eqn:10](eqn:10) and
[eqn:11](eqn:11). After that, we can verify the proof in the same way.
Now we have got rid of all the roadblocks. A zero-knowledge confidential
transaction scheme is here to stay.
