export function main(argv) {
    if (argv.length < 1) {
        return 1;
    }

    console.log(argv);
    let dest = argv[0];
    let rule = `https-sni-probe && eq \$\{REQ.dest_host\} \"${dest}\" && reject;`;
    console.log(rule);
    return rule;
}
