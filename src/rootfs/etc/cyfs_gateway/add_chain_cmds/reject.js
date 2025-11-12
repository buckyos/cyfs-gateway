export function main(argv) {
    if (argv.length < 1) {
        return 1;
    }

    let dest = argv[0];

    console.log(dest);
    let rule = `https-sni-probe && eq \$\{REQ.dest_host\} \"${dest}\" && reject;`;
    console.log(rule);
    return rule;
}
