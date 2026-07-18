import { Adversary } from "@adversarylabs/sdk";
import leftPad from "left-pad";
export const app = new Adversary({ name: leftPad("example", 8) });

