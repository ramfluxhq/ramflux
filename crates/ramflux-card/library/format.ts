// SPDX-License-Identifier: BSD-3-Clause
export function format(pattern:string,values:readonly (readonly [string,string])[]):string {
  const pieces=pattern.split("{");const first=pieces.shift()??"";
  return first+pieces.map(piece=>{const close=piece.indexOf("}");if(close<0)return "{"+piece;
    const name=piece.slice(0,close);return (values.find(value=>value[0]===name)?.[1]??"")+piece.slice(close+1)}).join("");
}
export function grouped(value:number,separator:string):string {
  const raw=value.toString(),negative=raw.startsWith("-"),digits=negative?raw.slice(1):raw;
  return (negative?"-":"")+digits.split("").map((c,index)=>(index>0&&(digits.length-index)%3===0?separator:"")+c).join("");
}
