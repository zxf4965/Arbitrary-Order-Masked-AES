/***************************************************************************
 * Implementation of Protected n-share AES-128 in C
 * 
 * This code is an implementation of a protected n-share AES-128 using 
 * compiled gadgets with the expanding circuit compiler introduced in:
 * 
 * "Random Probing Security: Verification, Composition, Expansion and New 
 * Constructions"
 * By Sonia Belaïd, Jean-Sébastien Coron, Emmanuel Prouff, Matthieu Rivain, 
 * and Abdul Rahman Taleb
 * In the proceedings of CRYPTO 2020.
 * 
 * Copyright (C) 2020 CryptoExperts
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 * 
 *  Modifications date: December 2024
 * 
 * Description of modifications:
 * - Enhanced `gadgets.c` by implementing an iterable gadget to improve functionality.
 * - Updated the implementation of the `void exp254_sharing(uint8_t *x, uint8_t * out)` function in `aes128_sharing.c` to change the order of the addition chain.

***************************************************************************/

#include "gadgets.h"
#include "gf256.h"

/**********************************************************
 * Creates a n-share randomized variable of
 *  the variable a, and stores it in the array a_sharing
**********************************************************/
void generate_n_sharing(uint8_t a, uint8_t * a_sharing){
	int i;
	uint8_t res = 0;
	for(i =0; i< NB_SHARES - 1; i++){
		a_sharing[i] = get_rand();
		res = res ^ a_sharing[i];
	}
	
	a_sharing[NB_SHARES - 1] = res ^ a;
}

/**********************************************************
 * Returns the value of the variable stored in the 
 * randomized n-share variable a_sharing (simply xors
 * all the shares)
**********************************************************/
uint8_t compress_n_sharing(uint8_t * a_sharing){
	int i=0;
	uint8_t a = 0;
	for(i=0; i<NB_SHARES; i++){
		a = a ^ a_sharing[i];
	}
	
	return a;
}



/**********************************************************
 * cons : constant value
 * a : n-share input variable
 * c : n-share output variable
 * Computes c = a + cons by creating a sharing of cons
 * as (cons, 0, ..., 0) and calling the addition gadget
**********************************************************/
void add_cons_gadget_function(uint8_t cons, uint8_t * a, uint8_t * c){

	const_s[0] = cons;
	
	add_gadget_function(const_s, a, c);
	
}


/**********************************************************
 * cons : constant value
 * a : n-share input variable
 * c : n-share output variable
 * Computes c = a * cons by creating a sharing of cons
 * as (cons, 0, ..., 0) and calling the 
 * multiplicaction gadget
**********************************************************/
void mult_cons_gadget_function(uint8_t cons, uint8_t * a, uint8_t * c){
	
	const_s[0] = cons;
	
	mult_gadget_function(a, const_s, c);
}


void add_gadget_function_2(uint8_t * a, uint8_t * b, uint8_t * c){
	uint8_t r0 = get_rand();
	uint8_t r1 = get_rand();
	uint8_t r2 = get_rand();
	uint8_t r3 = get_rand();

    uint8_t tmp = Add(r0,r2);
	uint8_t var0 = Add(a[0], tmp) ;
	tmp = Add(r1,r3);
	uint8_t var1 = Add(b[0], tmp) ;
	c[0] = Add(var0, var1) ;

    tmp = Add(r1,r2);
	var0 = Add(a[1], tmp) ;
	tmp = Add(r0,r3);
	var1 = Add(b[1], tmp) ;
	c[1] = Add(var0, var1) ;
}

void add_gadget_function_3(uint8_t * a, uint8_t * b, uint8_t * c){
	uint8_t r0 = get_rand();
	uint8_t r1 = get_rand();
	uint8_t r2 = get_rand();
	uint8_t r3 = get_rand();
	uint8_t r4 = get_rand();
	uint8_t r5 = get_rand();

	uint8_t var0 = Add(r0, r1) ;
	uint8_t var1 = Add(a[0], var0) ;
	uint8_t var2 = Add(r2, r3) ;
	uint8_t var3 = Add(b[0], var2) ;
	c[0] = Add(var1, var3) ;

	uint8_t var4 = Add(r2, r4) ;
	uint8_t var5 = Add(a[1], var4) ;
	uint8_t var6 = Add(r5, r1) ;
	uint8_t var7 = Add(b[1], var6) ;
	c[1] = Add(var5, var7) ;

	uint8_t var8 = Add(r5, r3) ;
	uint8_t var9 = Add(a[2], var8) ;
	uint8_t var10 = Add(r0, r4) ;
	uint8_t var11 = Add(b[2], var10) ;
	c[2] = Add(var9, var11) ;
}


void add_gadget_function(uint8_t * a, uint8_t * b, uint8_t * c){
    uint8_t m[3],n[3],k[3];
    int i = NB_SHARES/2;
    int r = NB_SHARES%2;
    for(int j = 0;j < i;j++){
        m[0] = a[j*2 + 0];
        m[1] = a[j*2 + 1];
        n[0] = b[j*2 + 0];
        n[1] = b[j*2 + 1];
        if(j != i - 1)
            add_gadget_function_2(m, n, k);
        else if(r == 0)
            add_gadget_function_2(m, n, k);
        else if(r == 1){
            m[2] = a[j*2 + 2];
            n[2] = b[j*2 + 2];
            add_gadget_function_3(m, n, k);
            c[j*2 + 2] = k[2];
        }
        c[j*2 + 0] = k[0];
        c[j*2 + 1] = k[1];
    }
    
    
  return 0;
}


/**********************************************************
 * cons : constant value
 * a : n-share input variable
 * c : n-share output variable
 * Computes c = a * cons by creating a sharing of cons
 * as (cons, 0, ..., 0) and calling the 
 * multiplicaction gadget
**********************************************************/


void copy_gadget_function_2(uint8_t * a, uint8_t * d, uint8_t * e){
	uint8_t r0 = get_rand();
	uint8_t r1 = get_rand();

	d[0] = Add(a[0], r0) ;
	e[0] = Add(a[0], r1) ;

	d[1] = Add(a[1], r0) ;
	e[1] = Add(a[1], r1) ;
}

void copy_gadget_function_3(uint8_t * a, uint8_t * d, uint8_t * e){
	uint8_t r0 = get_rand();
	uint8_t r1 = get_rand();
	uint8_t r2 = get_rand();
	uint8_t r3 = get_rand();
	uint8_t r4 = get_rand();
	uint8_t r5 = get_rand();

	uint8_t var0 = Add(r0, r1) ;
	uint8_t var1 = Add(r1, r2) ;
	uint8_t var2 = Add(r2, r0) ;
	uint8_t var3 = Add(r3, r4) ;
	uint8_t var4 = Add(r4, r5) ;
	uint8_t var5 = Add(r5, r3) ;

	d[0] = Add(a[0], var0) ;
	e[0] = Add(a[0], var3) ;

	d[1] = Add(a[1], var1) ;
	e[1] = Add(a[1], var4) ;

	d[2] = Add(a[2], var2) ;
	e[2] = Add(a[2], var5) ;
}


void copy_gadget_function(uint8_t * a, uint8_t * d, uint8_t * e){
    uint8_t m[3],n[3],k[3];
    int i = NB_SHARES/2;
    int r = NB_SHARES%2;
    for(int j = 0;j < i;j++){
        m[0] = a[j*2 + 0];
        m[1] = a[j*2 + 1];
        if(j != i - 1)
            copy_gadget_function_2(m, n, k);
        else if(r == 0)
            copy_gadget_function_2(m, n, k);
        else if(r == 1){
            m[2] = a[j*2 + 2];
            copy_gadget_function_3(m, n, k);
            d[j*2 + 2] = n[2];
            e[j*2 + 2] = k[2];
        }
        d[j*2 + 0] = n[0];
        d[j*2 + 1] = n[1];
        e[j*2 + 0] = k[0];
        e[j*2 + 1] = k[1];
    }
  
  return 0;
  
}

/**********************************************************
 * cons : constant value
 * a : n-share input variable
 * c : n-share output variable
 * Computes c = a * cons by creating a sharing of cons
 * as (cons, 0, ..., 0) and calling the 
 * multiplicaction gadget
**********************************************************/

void mult_gadget_function_2(uint8_t * a, uint8_t * b, uint8_t * c){
	uint8_t r0 = get_rand();
	uint8_t r1 = get_rand();
	uint8_t r2 = get_rand();
	uint8_t r3 = get_rand();
    
    uint8_t u0 = Add(a[0],r0);
    uint8_t u1 = Add(a[0],u0);
    uint8_t v0 = Add(b[0],r1);
    uint8_t v1 = Add(b[1],r1);
    
    uint8_t var0 = Multiply(u0, v0);
	uint8_t var1 = Multiply(u0, v1) ;
	uint8_t tmp1 = Add(var0,r2);
	uint8_t tmp2 = Add(var1,r3);
	c[0] = Add(tmp1, tmp2) ;

	uint8_t var2 = Multiply(u1, v0) ;
	uint8_t var3 = Multiply(u1, v1);
	tmp1 = Add(var2, r2);
	tmp2 = Add(var3,r3);
    c[1] = Add(tmp1, tmp2);
}

void mult_gadget_function_3(uint8_t * a, uint8_t * b, uint8_t * c){
	uint8_t r0 = get_rand();
	uint8_t r1 = get_rand();
	uint8_t r2 = get_rand();
	uint8_t r3 = get_rand();
	uint8_t r4 = get_rand();
	uint8_t r5 = get_rand();
	uint8_t r6 = get_rand();
	uint8_t r7 = get_rand();
	uint8_t r8 = get_rand();
	uint8_t r9 = get_rand();

    uint8_t tmp = Add(r0,r1);
    uint8_t u0 = Add(a[0],tmp);
    uint8_t u00 = Add(u0,a[0]);
    tmp = Add(r3,r4);
    uint8_t v0 = Add(b[0],tmp);

	uint8_t var0 = Multiply(u0, v0) ;
	uint8_t var1 = Multiply(u00, v0) ;
	uint8_t var2 = Add(var0,r6);
	uint8_t var3 = Add(var1,r7);
	c[0] = Add(var2, var3) ;


    tmp = Add(r1,r2);
    uint8_t u1 = Add(a[1],tmp);
    uint8_t u11 = Add(u1,a[1]);
    tmp = Add(r4,r5);
    uint8_t v1 = Add(b[1],tmp);

	var0 = Multiply(u1, v1) ;
	var1 = Multiply(u11, v1) ;
	var2 = Add(var0,r8);
	var3 = Add(var1,r9);
	c[1] = Add(var2, var3) ;


    tmp = Add(r2,r0);
    uint8_t u2 = Add(a[2],tmp);
    uint8_t u22 = Add(u2,a[2]);
    tmp = Add(r5,r3);
    uint8_t v2 = Add(b[2],tmp);

	var0 = Multiply(u2, v2) ;
	var1 = Multiply(u22, v2) ;
	tmp = Add(r6,r8);
	var2 = Add(var0,tmp);
	tmp = Add(r7,r9);
	var3 = Add(var1,tmp);
	c[2] = Add(var2, var3) ;
	
}

void mult_gadget_function(uint8_t * a, uint8_t * b, uint8_t * c){
    uint8_t r0 = get_rand();
	uint8_t r1 = get_rand();
	
	uint8_t var[3];
    uint8_t m[3],n[3],k[3];
    int i = NB_SHARES/2;
    int r = NB_SHARES%2;
    for(int p = 0;p < NB_SHARES;p++){
        c[p] = 0;
        for(int q = 0;q < i;q++){
            m[0] = a[p];
            m[1] = a[p];
            n[0] = b[q*2 + 0];
            n[1] = b[q*2 + 1];
            if(q != i - 1){
                mult_gadget_function_2(m, n, k);
                var[0] = Add(k[0],r0);
                c[p] = Add(c[p],var[0]);
                var[1] = Add(k[1],r0);
                c[p] = Add(c[p],var[1]);
            }
            else if(r == 0){
                mult_gadget_function_2(m, n, k);
                var[0] = Add(k[0],r0);
                c[p] = Add(c[p],var[0]);
                var[1] = Add(k[1],r0);
                c[p] = Add(c[p],var[1]);
            }
            else if(r == 1){
                m[2] = a[p];
                n[2] = b[q*2 + 2];
                mult_gadget_function_3(m, n, k);
                var[0] = Add(k[0],r0);
                c[p] = Add(c[p],var[0]);
                var[1] = Add(k[1],r1);
                c[p] = Add(c[p],var[1]);
                var[2] = Add(r0,r1);
                var[2] = Add(k[2],var[2]);
                c[p] = Add(c[p],var[2]);
            }
        }
    }
    
  return 0;
}
